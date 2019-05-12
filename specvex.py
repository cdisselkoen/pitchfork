import angr
import pyvex
import claripy
from angr.errors import SimReliftException, UnsupportedIRStmtError, SimStatementError
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from angr.state_plugins.sim_action_object import SimActionObject
from angr.state_plugins.sim_action import SimActionData
from angr.engines import vex

import collections

import logging
l = logging.getLogger(name=__name__)

class SimEngineSpecVEX(angr.SimEngineVEX):
    """
    Execution engine which allows bounded wrong-path speculation.
    Based on the default SimEngineVEX.
    """

    def _handle_statement(self, state, successors, stmt):
        """
        An override of the _handle_statement method in SimEngineVEX base class.
        Much code copied from there; see SimEngineVEX class for more information/docs.
        """

        if type(stmt) == pyvex.IRStmt.IMark:
            ins_addr = stmt.addr + stmt.delta
            state.scratch.ins_addr = ins_addr

            # Raise an exception if we're suddenly in self-modifying code
            for subaddr in range(stmt.len):
                if subaddr + stmt.addr in state.scratch.dirty_addrs:
                    raise SimReliftException(state)
            state._inspect('instruction', BP_AFTER)

            #l.debug("IMark: %#x", stmt.addr)
            state.scratch.num_insns += 1
            state._inspect('instruction', BP_BEFORE, instruction=ins_addr)

            if state.spec.mispredicted:
                return False  # report path as deadended

        # process it!
        try:
            stmt_handler = self.stmt_handlers[stmt.tag_int]
        except IndexError:
            l.error("Unsupported statement type %s", (type(stmt)))
            if angr.options.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
                raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
            state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
            return None
        else:
            exit_data = stmt_handler(self, state, stmt)

        # handling conditional exits is where the magic happens
        if exit_data is not None and len(exit_data) == 3:
            target, guard, jumpkind = exit_data

            l.debug("time {}: forking for conditional exit to {} under guard {}".format(state.spec.ins_executed, target, guard))

            # Unlike normal SimEngineVEX, we always proceed down both sides of the branch
            # (to simulate possible wrong-path execution, i.e. branch misprediction)
            # and add the path constraints later, only after _spec_window_size instructions have passed

            exit_state = state.copy()
            cont_state = state

            branchcond = guard
            notbranchcond = claripy.Not(branchcond)
            if not state.solver.is_true(branchcond): exit_state.spec.conditionals.append(branchcond)  # don't bother adding a deferred 'True' constraint
            if not state.solver.is_true(notbranchcond): cont_state.spec.conditionals.append(notbranchcond)  # don't bother adding a deferred 'True' constraint

            successors.add_successor(exit_state, target, guard, jumpkind, add_guard=False,
                                    exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr)

            # We don't add the guard for the exit_state (add_guard=False).
            # Unfortunately, the call to add the 'default' successor at the end of an irsb
            # (line 313 in vex/engine.py as of this writing) leaves add_guard as default (True).
            # For the moment, rather than patching this, we just don't record the guard at
            # all on the cont_state.
            # TODO not sure if this will mess us up. Is scratch.guard used for merging?
            # Haven't thought about how speculation should interact with merging.
            # More fundamentally, what is scratch.guard used for when add_guard=False? Anything?
            #cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, notbranchcond)

        elif exit_data is not None and len(exit_data) > 3:
            # a tremendous hack, see notes in angr/engines/vex/statements/loadg.py
            # but here we do forking for loads, to account for the various forwarding possibilities
            (stmt, addr, read_expr, alt, guard, read_size_bits, converted_size_bits, addr_deps, alt_deps, guard_deps) = exit_data
            if guard is not None and not guard.is_true():
                raise ValueError("not implemented yet: conditional load")
            for (l_state, l_value) in read_expr:
                # we finish the load, performing all the steps we skipped in angr/engines/vex/statements/loadg.py, see notes there
                if read_size_bits == converted_size_bits:
                    converted_expr = l_value
                elif "S" in stmt.cvt:
                    converted_expr = l_value.sign_extend(converted_size_bits - read_size_bits)
                elif "U" in stmt.cvt:
                    converted_expr = l_value.zero_extend()
                else:
                    raise SimStatementError("Unrecognized IRLoadGOp %s!" % stmt.cvt)
                l_value = l_state.solver.If(guard != 0, converted_expr, alt)
                l_state.scratch.store_tmp(stmt.dst, l_value, deps=addr_deps +  alt_deps + guard_deps)
                if angr.options.TRACK_MEMORY_ACTIONS in l_state.options:
                    data_ao = SimActionObject(converted_expr)
                    alt_ao = SimActionObject(alt, deps=alt_deps, state=l_state)
                    addr_ao = SimActionObject(addr, deps=addr_deps, state=l_state)
                    guard_ao = SimActionObject(guard, deps=guard_deps, state=l_state)
                    size_ao = SimActionObject(converted_size_bits)
                    r = SimActionData(l_state, l_state.memory.id, SimActionData.READ, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao, fallback=alt_ao)
                    l_state.history.add_action(r)

                if l_state is not state:
                    target = stmt.addr + stmt.delta  # next instruction
                    jumpkind = 'Ijk_Boring'  # seems like a reasonable choice? what is this used for?
                    successors.add_successor(l_state, target, True, jumpkind, add_guard=False, exit_stmt_idx=None, exit_ins_addr=None)

        return True

class SpecState(angr.SimStatePlugin):
    def __init__(self, spec_window_size, ins=0, conditionals=None, stores=None):
        """
        Members:
        _spec_window_size: speculative window size. Maximum number of x86
            instructions we can go past a misprediction point.
        ins_executed: number of x86 instructions executed since start
        conditionals: a data structure where we track inflight conditionals
            (predictions we've made). A SpecQueue where thing = conditional guard
        stores: a data structure where we track inflight stores.
            A SpecQueue where thing = (addr, value, cond, endness, action, poisoned)
            poisoned is a bool, if True then this store will cause rollback (cause this
            state to abort) when it retires. When we mis-forward from a store or from
            memory, we set the poisoned bit on the _next_ store to that address, because
            that's the latest time we could realize we were wrong.
            As of this writing, this all relies on modifications to angr itself,
            particularly for the forwarding.
        """
        super().__init__()
        self._spec_window_size = spec_window_size
        self.ins_executed = ins
        if conditionals is not None:
            self.conditionals = conditionals
        else:
            self.conditionals = SpecQueue(ins)
        if stores is not None:
            self.stores = stores
        else:
            self.stores = SpecQueue(ins)
        self.mispredicted = False

    def arm(self, state, misforwarding=False):
        state.inspect.b('instruction', when=BP_BEFORE, action=tickSpecState)
        state.inspect.b('statement', when=BP_BEFORE, action=handleFences)
        if misforwarding:
            state.register_plugin('store_hook', StoreHook())
            state.register_plugin('load_hook', LoadHook())

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpecState(
            spec_window_size=self._spec_window_size,
            ins=self.ins_executed,
            conditionals=self.conditionals.copy(),
            stores=self.stores.copy()
        )

    def tick(self):
        # we count instructions executed here because I couldn't find an existing place (e.g. state.history) where instructions are counted.
        # (TODO state.scratch.num_insns? is the 'scratch' reliably persistent?)
        # Also, this may miss instructions handled by other engines, but TODO that is presumably few?
        self.ins_executed += 1
        self.conditionals.tick()
        self.stores.tick()

class SpecQueue:
    """
    holds "things" which are currently in-flight/unresolved
    """
    def __init__(self, ins_executed=0, q=None):
        self.ins_executed = ins_executed
        if q is None:
            self.q = collections.deque()
        else:
            self.q = q

    def copy(self):
        return SpecQueue(ins_executed=self.ins_executed, q=self.q.copy())

    def tick(self):
        self.ins_executed += 1

    def append(self, thing):
        self.q.append((thing, self.ins_executed))

    def ageOfOldest(self):
        if self.q:
            (_, whenadded) = self.q[0]  # peek
            return self.ins_executed - whenadded
        else:
            return None

    def popOldest(self):
        (thing, _) = self.q.popleft()
        return thing

    def popAll(self):
        """
        A generator that pops each thing and yields it
        """
        while self.q:
            (thing, _) = self.q.popleft()
            yield thing

    def getAt(self, i):
        """
        Return the i'th entry in the queue, where 0 is the oldest
        """
        return self.q[i]

    def updateAt(self, i, lam):
        """
        Update the i'th entry by applying the given lambda to it
        """
        self.q[i] = lam(self.q[i])

def tickSpecState(state):
    # Keep track of how many instructions we have executed
    state.spec.tick()

    # See if it is time to retire the oldest conditional, that is, end possible wrong-path execution
    age = state.spec.conditionals.ageOfOldest()
    while age and age > state.spec._spec_window_size:
        cond = state.spec.conditionals.popOldest()
        l.debug("time {}: adding deferred conditional (age {}): {}".format(state.spec.ins_executed, age, cond))
        state.add_constraints(cond)
        # See if the newly added constraint makes us unsat, if so, kill this state
        if angr.sim_options.LAZY_SOLVES not in state.options and not state.solver.satisfiable():
            l.debug("time {}: killing mispredicted path: constraints not satisfiable: {}".format(state.spec.ins_executed, state.solver.constraints))
            state.spec.mispredicted = True
            return
        age = state.spec.conditionals.ageOfOldest()  # check next conditional

    # See if it is time to retire the oldest store, so future loads can no longer possibly see the previous value
    #   (they will get this value or newer)
    age = state.spec.stores.ageOfOldest()
    while age and age > state.spec._spec_window_size:
        addr, value, cond, endness, action, poisoned = state.spec.stores.popOldest()
        if poisoned:  # see notes on SpecState
            l.debug("time {}: killing path due to incorrect forwarding".format(state.spec.ins_executed))
            state.spec.mispredicted = True
            return
        else:
            l.debug("time {}: performing deferred store (age {}): address {}, data {}, condition {}".format(state.spec.ins_executed, age, addr, value, cond))
            state.memory.store(addr, value, condition=cond, endness=endness, action=action)
        age = state.spec.stores.ageOfOldest()  # check next store

def handleFences(state):
    """
    A hook watching for fence instructions, don't speculate past fences
    """
    stmt = state.scratch.irsb.statements[state.inspect.statement]
    if type(stmt) == pyvex.stmt.MBE and stmt.event == "Imbe_Fence":
        l.debug("time {}: encountered a fence, flushing all deferred constraints and stores".format(state.spec.ins_executed))
        state.add_constraints(*list(state.spec.conditionals.popAll()))
        # See if this has made us unsat, if so, kill this state
        if angr.sim_options.LAZY_SOLVES not in state.options and not state.solver.satisfiable():
            l.debug("time {}: killing mispredicted path: constraints not satisfiable: {}".format(state.spec.ins_executed, state.solver.constraints))
            state.spec.mispredicted = True
            return
        for (addr, value, cond, endness, action, poisoned) in state.spec.stores.popAll():
            if poisoned:  # see notes on SpecState
                l.debug("time {}: killing path due to incorrect forwarding".format(state.spec.ins_executed))
                state.spec.mispredicted = True
                return
            else:
                state.memory.store(addr, value, condition=cond, endness=endness, action=action)

class StoreHook(angr.SimStatePlugin):
    """
    Allows hooking store operations.
    (requires our fork of angr to actually respect the hook)
    """
    def do_store(self, state, addr, expr, condition, endness, action):
        state.spec.stores.append((addr, expr, condition, endness, action, False))

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return StoreHook()

class LoadHook(angr.SimStatePlugin):
    """
    Allows hooking load operations.
    (requires our fork of angr to actually respect the hook)
    """
    def do_load(self, state, addr, read_size, endness, condition):
        # we will return a list of pairs (state, read_expr), knowing that thanks to our hack our modified engine will get to handle them
        returnPairs = []
        # one valid option is to read from memory, ignoring all inflight stores (not forwarding)
        returnPairs.append(state, state.memory.load(addr, read_size, endness=endness, condition=condition))
        # 'correct_state' will be continuously updated, but it always stores our current idea of which state has the 'correct' (not mis-speculated) load value
        correct_state = state
        for (storenum, (s_addr, s_value, s_cond, s_endness, _, _)) in enumerate(state.spec.stores.getAllOldestFirst()):
            s_size = state.arch.bits // 8 # my read of angr/storage/memory.py (SimMemory.store()) shows that all stores are size state.arch.bits (in bits), since when VEX processes store statements it never passes an explicit size to SimMemory.store()?
            if not overlaps(addr, read_size, s_addr, s_size): continue
            if addr != s_addr or read_size != s_size:
                raise ValueError("not yet implemented: load overlaps with an inflight store but is not to identical address/size")
            if endness != s_endness:
                raise ValueError("not yet implemented: load and store differ in endness")
            if s_cond is not None and not s_cond.is_true():
                raise ValueError("not yet implemented: conditional store")

            # fork a new state, that will forward from this inflight store
            forwarding_state = correct_state.copy()  # we use correct_state because nothing is poisoned there yet
            # the previous 'correct' state must discover that it's incorrect when this store retires, at the latest
            correct_state.spec.stores.updateAt(storenum, poison)
            # we are now the 'correct' state, to our knowledge -- we have the most recently stored value to this address
            correct_state = forwarding_state
            # we are a valid state, and this is the value we think the load has
            returnPairs.append(forwarding_state, s_value)
        return returnPairs

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return LoadHook()

def overlaps(addrA, sizeInBytesA, addrB, sizeInBytesB):
    if addrA + sizeInBytesA <= addrB: return False
    if addrA > addrB + sizeInBytesB: return False
    return True

def poison(store):
    (addr, value, cond, endness, action, _) = store
    return (addr, value, cond, endness, action, True)
