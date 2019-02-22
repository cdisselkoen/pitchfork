import angr
import pyvex
import claripy
from angr.errors import SimReliftException
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from angr.engines import vex

import collections

import logging
l = logging.getLogger(name=__name__)

class SimEngineSpecVEX(angr.SimEngineVEX):
    """
    Execution engine which allows bounded wrong-path speculation.
    Based on the default SimEngineVEX.
    """

    def __init__(self, spec_window_size, **kwargs):
        super().__init__(**kwargs)
        self._spec_window_size = spec_window_size

    def _handle_statement(self, state, successors, stmt):
        """
        An override of the _handle_statement method in SimEngineVEX base class.
        Much code copied from there; see SimEngineVEX class for more information/docs.
        """

        # Keep track of how many instructions we have executed
        state.spec.tick()

        # See if it is time to retire the oldest conditional, that is, end possible wrong-path execution
        # Note since we only add <= 1 conditional at each time step, we don't need to worry about retiring
        # multiple conditionals in a single timestep
        age = state.spec.ageOfOldestConditional()
        if age and age > self._spec_window_size:
            l.debug("%s now adding deferred conditional", self)
            cond = state.spec.popOldestConditional()
            state.add_constraints(cond)
            # See if the newly added constraint makes us unsat, if so, kill this state
            if angr.sim_options.LAZY_SOLVES not in state.options and not state.solver.satisfiable():
                l.debug("killing mispredicted path")
                return False

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

        # process it!
        s_stmt = vex.statements.translate_stmt(stmt, state)
        if s_stmt is not None:
            state.history.extend_actions(s_stmt.actions)

        # handling conditional exits is where the magic happens
        if type(stmt) == pyvex.IRStmt.Exit:
            l.debug("%s forking for conditional exit", self)

            # Unlike normal SimEngineVEX, we always proceed down both sides of the branch
            # (to simulate possible wrong-path execution, i.e. branch misprediction)
            # and add the path constraints later, only after _spec_window_size instructions have passed

            exit_state = state.copy()
            cont_state = state

            branchcond = s_stmt.guard
            notbranchcond = claripy.Not(branchcond)
            exit_state.spec.append(branchcond)
            cont_state.spec.append(notbranchcond)

            successors.add_successor(exit_state, s_stmt.target, s_stmt.guard, s_stmt.jumpkind, add_guard=False,
                                    exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr)

            # We don't add the guard for the exit_state (add_guard=False).
            # Unfortunately, the call to add the 'default' successor at the end of an irsb
            # (line 311 in vex/engine.py as of this writing) leaves add_guard as default (True).
            # For the moment, rather than patching this, we just don't record the guard at
            # all on the cont_state.
            # TODO not sure if this will mess us up. Is scratch.guard used for merging?
            # Haven't thought about how speculation should interact with merging.
            # More fundamentally, what is scratch.guard used for when add_guard=False? Anything?
            #cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, notbranchcond)

        return True

    #
    # Pickling
    #

    def __setstate__(self, state):
        self._spec_window_size = state['_spec_window_size']
        super().__setstate__(state)

    def __getstate__(self):
        s = super().__getstate__()
        s['_spec_window_size'] = self._spec_window_size

class SpecState(angr.SimStatePlugin):
    def __init__(self, ins=0, conds=None):
        super().__init__()
        self.ins_executed = ins  # we track this here because I couldn't find an existing place (e.g. state.history) where instructions are counted. This may miss instructions handled by other engines, but TODO that is presumably few?
        if conds:
          self.conditionals = conds
        else:
          self.conditionals = collections.deque()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpecState(self.ins_executed, self.conditionals)

    def tick(self):
        self.ins_executed += 1

    def append(self, condition):
        self.conditionals.append((condition, self.ins_executed))

    def ageOfOldestConditional(self):
        if self.conditionals:
            (_, whenadded) = self.conditionals[0]  # peek
            return self.ins_executed - whenadded
        else:
            return None

    def popOldestConditional(self):
        (cond, _) = self.conditionals.popleft()
        return cond
