import angr
import pyvex
import claripy
from angr.errors import SimReliftException, UnsupportedIRStmtError, SimStatementError, SimUninitializedAccessError
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from angr.state_plugins.sim_action_object import SimActionObject
from angr.state_plugins.sim_action import SimActionData
from angr.engines import vex

import collections
import logging
l = logging.getLogger(name=__name__)

from utils import isDefinitelyEqual_Solver, isDefinitelyNotEqual_Solver, describeAst

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

        if type(stmt) == pyvex.IRStmt.WrTmp and type(stmt.data) == pyvex.IRExpr.Load:
            # we duplicate the processing for this ourselves, because we potentially need to fork during load processing
            load = stmt.data
            with state.history.subscribe_actions() as data_deps:
                state._inspect('expr', BP_BEFORE, expr=load)
                load_size_bits = pyvex.const.get_type_size(load.type)
                load_size_bytes = load_size_bits // state.arch.byte_width
                with state.history.subscribe_actions() as addr_actions:
                    addr = self.handle_expression(state, load.addr)
                if angr.options.UNINITIALIZED_ACCESS_AWARENESS in state.options:
                    if getattr(addr._model_vsa, 'uninitialized', False):
                        raise SimUninitializedAccessError('addr', addr)
                if angr.options.DO_LOADS not in state.options:
                    results = (state, state.solver.Unconstrained("load_expr_%#x_%d" % (state.scratch.ins_addr, state.scratch.stmt_idx), load_size_bits))
                else:
                    results = performLoadWithPossibleForwarding(state, addr, load_size_bytes, load_endness=load.endness)

                for (l_state, l_value) in results:
                    if load.type.startswith('Ity_F'):
                        l_value = l_value.raw_to_fp()
                    if angr.options.TRACK_MEMORY_ACTIONS in l_state.options:
                        addr_ao = SimActionObject(addr, deps=addr_actions, state=l_state)
                        r = SimActionData(l_state, l_state.memory.id, SimActionData.READ, addr=addr_ao, size=load_size_bits, data=l_value)
                        l_state.history.add_action(r)
                    if angr.options.SIMPLIFY_EXPRS in l_state.options:
                        l_value = state.solver.simplify(l_value)
                    if l_state.solver.symbolic(l_value) and angr.options.CONCRETIZE in l_state.options:
                        concrete_value = l_state.solver.BVV(l_state.solver.eval(l_value), len(l_value))
                        l_state.add_constraints(l_value == concrete_value)
                        l_value = concrete_value
                    l_state._inspect('expr', BP_AFTER, expr=load, expr_result=l_value)
                    l_state.scratch.store_tmp(stmt.tmp, l_value, deps=data_deps)

                    # now we tell angr about the fork, so it continues executing the state
                    if l_state is not state:
                        target = nextInstruction(state, stmt)
                        jumpkind = 'Ijk_Boring'  # seems like a reasonable choice? what is this used for?
                        guard = claripy.BVV(1, 1)  # boolean True
                        l.debug("time {}: forking for misforwarding".format(state.spec.ins_executed))
                        successors.add_successor(l_state, target, guard, jumpkind, add_guard=False, exit_stmt_idx=None, exit_ins_addr=None)

            # we've now completely handled this statement manually, we're done
            return True

        if type(stmt) == pyvex.IRStmt.LoadG:
            # we also duplicate the processing for this ourselves, because we potentially need to fork during load processing
            with state.history.subscribe_actions() as addr_deps:
                addr = self.handle_expression(state, stmt.addr)
            with state.history.subscribe_actions() as alt_deps:
                alt = self.handle_expression(state, stmt.alt)
            with state.history.subscribe_actions() as guard_deps:
                guard = self.handle_expression(state, stmt.guard)
            if guard is not None and state.solver.satisfiable(extra_constraints=[claripy.Not(guard)]):
                raise ValueError("not implemented yet: conditional load with condition that could be false")

            read_type, converted_type = stmt.cvt_types
            read_size_bits = pyvex.const.get_type_size(read_type)
            converted_size_bits = pyvex.const.get_type_size(converted_type)
            read_size = read_size_bits // state.arch.byte_width

            results = performLoadWithPossibleForwarding(state, addr, read_size, load_endness=stmt.end)

            for (l_state, l_value) in results:
                if read_size_bits == converted_size_bits:
                    converted_expr = l_value
                elif "S" in stmt.cvt:
                    converted_expr = l_value.sign_extend(converted_size_bits - read_size_bits)
                elif "U" in stmt.cvt:
                    converted_expr = l_value.zero_extend()
                else:
                    raise SimStatementError("Unrecognized IRLoadGOp %s!" % stmt.cvt)
                l_value = l_state.solver.If(guard != 0, converted_expr, alt)
                l_state.scratch.store_tmp(stmt.dst, l_value, deps=addr_deps + alt_deps + guard_deps)
                if angr.options.TRACK_MEMORY_ACTIONS in l_state.options:
                    data_ao = SimActionObject(converted_expr)
                    alt_ao = SimActionObject(alt, deps=alt_deps, state=l_state)
                    addr_ao = SimActionObject(addr, deps=addr_deps, state=l_state)
                    guard_ao = SimActionObject(guard, deps=guard_deps, state=l_state)
                    size_ao = SimActionObject(converted_size_bits)
                    r = SimActionData(l_state, l_state.memory.id, SimActionData.READ, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao, fallback=alt_ao)
                    l_state.history.add_action(r)

                # now we tell angr about the fork, so it continues executing the state
                if l_state is not state:
                    target = nextInstruction(state, stmt)
                    jumpkind = 'Ijk_Boring'  # seems like a reasonable choice? what is this used for?
                    guard = claripy.BVV(1, 1)  # boolean True
                    l.debug("time {}: forking for misforwarding".format(state.spec.ins_executed))
                    successors.add_successor(l_state, target, guard, jumpkind, add_guard=False, exit_stmt_idx=None, exit_ins_addr=None)

            # we've now completely handled this statement manually, we're done
            return True

        # now for everything else
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
        if exit_data is not None:
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

        return True

def nextInstruction(state, stmt):
    # seems really inefficient; there's probably a better way
    foundThisStmt = False
    for s in state.scratch.irsb.statements:
        if foundThisStmt and type(s) is pyvex.stmt.IMark:
            return s.addr
        if s is stmt:
            foundThisStmt = True

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
        (thing, time) = self.q[i]
        self.q[i] = (lam(thing), time)

    def getAllOldestFirst(self):
        """
        Yield all of the things in the queue, oldest first
        """
        for (thing, _) in self.q:
            yield thing

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
        l.debug("time {}: deferring a store of {} to addr {}".format(state.spec.ins_executed, describeAst(expr), describeAst(addr)))
        state.spec.stores.append((addr, expr, condition, endness, action, False))
        # this is also hacky, but works for our purposes:
        # SpectreExplicitState wants the inspect points on 'mem_write' to trigger _now_
        #   even though we may or may not (semantically) be doing / have done the store now.
        #   (Future loads will consider both the possibility that we have or have not done
        #   this store, until it drops out of the speculation window.)
        # The inspect point will trigger again when the store drops out of the speculation
        #   window, and it's theoretically bad to trigger it twice, but doesn't do any harm
        #   for our uses, so for now it's fine.
        state._inspect('mem_write', BP_BEFORE,
            mem_write_address=addr,
            mem_write_length=len(expr) // 8,
            mem_write_expr=expr,
            mem_write_condition=condition
        )
        state._inspect('mem_write', BP_AFTER)  # angr/storage/memory.py passes only these arguments to the BP_AFTER point, so we do the same here for consistency

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return StoreHook()

class LoadHook(angr.SimStatePlugin):
    """
    Allows hooking load operations.
    (requires our fork of angr to actually respect the hook)
    """
    def do_load(self, state, addr, read_size, endness, condition):
        if condition is not None and state.solver.satisfiable(extra_constraints=[claripy.Not(condition)]):
            raise ValueError("not yet implemented: conditional load with condition that could be false")
        # we directly return pairs (state, load_value), knowing that thanks to our hack our modified engine will get to handle them
        return performLoadWithPossibleForwarding(state, addr, read_size, endness)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return LoadHook()

def performLoadWithPossibleForwarding(state, load_addr, load_size_bytes, load_endness):
    """
    returns: list of pairs (state, load_value)
    """
    l.debug("time {}: handling load of addr {}".format(state.spec.ins_executed, load_addr))
    returnPairs = []
    # one valid option is to read from memory, ignoring all inflight stores (not forwarding)
    memory_value = state.memory.load(load_addr, load_size_bytes, endness=load_endness)
    returnPairs.append((state, memory_value))
    # 'correct_state' will be continuously updated, but it always stores our current idea of which state has the 'correct' (not mis-speculated) load value
    correct_state = state
    correct_value = memory_value
    # explained later
    notOverlapStates = []
    stores = list(enumerate(state.spec.stores.getAllOldestFirst()))  # collect them into a list once right away, so then we aren't worrying about iterating over state.spec.stores while modifying it
    for (storenum, (s_addr, s_value, s_cond, s_endness, _, _)) in stores:
        l.debug("  - checking whether it could alias with store of {} to {}".format(describeAst(s_value), describeAst(s_addr)))
        s_size_bytes = len(s_value) // 8
        loadOverlapsStore = overlaps(load_addr, load_size_bytes, s_addr, s_size_bytes)
        if not correct_state.solver.satisfiable(extra_constraints=[loadOverlapsStore]):
            # it is impossible for the load to overlap this store
            continue

        if s_cond is not None and correct_state.solver.satisfiable(extra_constraints=[claripy.Not(s_cond)]):
            raise ValueError("not yet implemented: conditional store where condition could be False")
        if correct_state.solver.symbolic(load_size_bytes):
            raise ValueError("not yet implemented: load could overlap with an inflight store but has symbolic size")
        if correct_state.solver.symbolic(s_size_bytes):
            raise ValueError("not yet implemented: load could overlap with an inflight store, but store has symbolic size")
        if load_size_bytes > s_size_bytes:
            l.warn("load could overlap with an inflight store, but load is larger. We are only considering the case where they do not overlap. This will miss some possible speculative paths.")
            for (s, _) in returnPairs: s.add_constraints(claripy.Not(loadOverlapsStore))
            continue

        # if we got here, the load may overlap the store, but doesn't necessarily have to
        if correct_state.solver.satisfiable(extra_constraints=[claripy.Not(loadOverlapsStore)]):
            # in this case, it's possible both that the load either does or does not overlap the store
            # We create a notOverlapState, for which forwarding from the previous store was _actually correct_
            #   (it will not alias with this store or any newer inflight stores)
            # (We could also consider the possibility that the load not-aliases with this
            #   store and does-alias with a newer inflight store, but that would lead to a
            #   lot more blowup and it's unclear it would be useful. We're approximating
            #   elsewhere anyway, e.g. concretization)
            notOverlapState = correct_state.copy()
            notOverlapStates.append(notOverlapState)
            returnPairs.append((notOverlapState, correct_value))  # it reads the previous correct value
            # on the other hand, the other states are going to assume the load and store alias, so we should constrain that
            # (we add this before the fork that will happen below, because both of the forked states assume that the aliasing happens)
            correct_state.add_constraints(loadOverlapsStore)

        for s in notOverlapStates:
            # all of these states got their _correct values_ already, so they cannot alias with this store
            s.add_constraints(claripy.Not(loadOverlapsStore))

        # now we're left with the case where the load does overlap the store

        if isDefinitelyNotEqual_Solver(correct_state, load_addr, s_addr):
            raise ValueError("not yet implemented: load overlaps with an inflight store but cannot be identical address")
        elif not isDefinitelyEqual_Solver(correct_state, load_addr, s_addr):
            l.warn("load could overlap with store misaligned, but we are only considering the aligned case")
            # we choose to only consider cases where they're exactly equal, so we add that constraint
            correct_state.add_constraints(load_addr == s_addr)

        # fork a new state, that will forward from this inflight store
        forwarding_state = correct_state.copy()  # note that nothing is poisoned in correct_state yet
        # the previous 'correct' state must discover that it's incorrect when this store retires, at the latest
        #   (since it _definitely does_ alias with this store -- either that was already the case, or we constrained it to be so)
        correct_state.spec.stores.updateAt(storenum, poison)
        # we are now the 'correct' state, to our knowledge -- we have the most recently stored value to this address
        correct_state = forwarding_state
        # we are a valid state, and this is the value we think the load has
        returnPairs.append((forwarding_state, alignedLoadFromStoredValue(load_size_bytes, s_value, s_size_bytes, load_endness, s_endness)))
    l.debug("  - final returnPairs: {}".format(returnPairs))
    return returnPairs

def overlaps(addrA, sizeInBytesA, addrB, sizeInBytesB):
    """
    Returns a symbolic constraint representing the two intervals overlapping.
    If this constraint is simply True, then the intervals must overlap; if it is False, they cannot;
        and if it is some symbolic expression that may take either value, that expression encodes the
        condition under which they overlap.
    """
    a_left = addrA
    a_right = addrA + sizeInBytesA
    b_left = addrB
    b_right = addrB + sizeInBytesB
    return claripy.And(a_right > b_left, a_left < b_right)

def poison(store):
    (addr, value, cond, endness, action, _) = store
    return (addr, value, cond, endness, action, True)

def alignedLoadFromStoredValue(load_size_bytes, stored_value, stored_size_bytes, load_endness, store_endness):
    """
    Return the correct data when loading from the given stored_value, when sizes may be different.
    Assumes the load and store were to the _same address_.
    Also assumes load_size <= stored_size (otherwise we don't have all the data needed).
    """
    if load_endness != store_endness:
        raise ValueError("not yet implemented: load and store have different endianness")
    if len(stored_value) != stored_size_bytes * 8:
        raise ValueError("expected stored_value to be size {} bytes, got size {} bits".format(stored_size_bytes, len(stored_value)))
    if load_size_bytes == stored_size_bytes: return stored_value

    # This is mostly a guess at what the correct way to do this is
    # Note many things interacting here: endianness of the load, endianness of the store,
    #   the fact that angr reverses bitvectors on loads and stores depending on endianness,
    #   the comment on claripy.ast.bv.BV that for an AST 'a', a[31] is the LEFT-most (or most-significant) bit,
    #   the fact that the first argument to get_bytes() is always in big-endian order regardless of system endianness...
    return stored_value.get_bytes(0, load_size_bytes)
