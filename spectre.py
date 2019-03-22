import angr
import claripy
import pyvex

from oob import OOBStrategy, can_be_oob, concretization_succeeded, log_concretization
from taint import taintedUnconstrainedBits, is_tainted
from utils import isAst, describeAst

import logging
l = logging.getLogger(name=__name__)

class SpectreOOBState(angr.SimStatePlugin):
    """
    State tracking for Spectre gadget vulnerability detection.
    This plugin treats all uninitialized memory as secret, everything else as
    public.
    (This generally works because most of the time, any useful Spectre gadget
    is flexible enough that it can be made to leak data in *some*
    uninitialized and/or unmapped part of the virtual address space.)

    This plugin relies on the OOB state plugin existing (but not necessarily
    being 'armed').
    """

    def __init__(self, armed=False):
        super().__init__()
        self._armed = armed
        self.violation = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpectreOOBState(armed=self._armed)

    def arm(self, state):
        """
        Setup hooks and breakpoints to perform Spectre gadget vulnerability detection.
        Also set up concretization to ensure addresses are always made to be OOB when possible.
        """
        state.inspect.b('mem_read',  when=angr.BP_AFTER, condition=_tainted_read, action=detected_spectre_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_tainted_write, action=detected_spectre_write)
        state.inspect.b('exit', when=angr.BP_BEFORE, condition=_tainted_branch, action=detected_spectre_branch)

        state.memory.read_strategies.insert(0, OOBStrategy())
        state.memory.write_strategies.insert(0, OOBStrategy())
        state.inspect.b('address_concretization', when=angr.BP_AFTER, condition=concretization_succeeded, action=log_concretization)

        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        state.options.add(angr.options.SPECIAL_MEMORY_FILL)
        state._special_memory_filler = oob_memory_fill
        state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed

def oob_memory_fill(name, bits, state):
    return taintedUnconstrainedBits(state, name, bits)

class SpectreExplicitState(angr.SimStatePlugin):
    """
    State tracking for Spectre vulnerability detection.
    This plugin treats some particular range(s) of memory addresses as secret
    (explicitly specified as an argument to the constructor), and everything else
    as public.
    Useful to e.g. determine if a Spectre gadget exists that can leak the secret
    cryptographic key stored in a particular location.

    This plugin does not rely on the OOB state plugin in any way.
    """

    def __init__(self, secretIntervals, armed=False):
        """
        secretIntervals: Iterable of pairs (min, max) denoting ranges of memory to be
        considered 'secret'
        """
        super().__init__()
        self.secretIntervals = secretIntervals
        self._armed = armed
        self.violation = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpectreExplicitState(self.secretIntervals, armed=self._armed)

    def arm(self, state):
        """
        Setup hooks and breakpoints to perform Spectre gadget vulnerability detection.
        Also set up concretization to ensure addresses always point to secret data when possible.
        """
        state.inspect.b('mem_read',  when=angr.BP_AFTER, condition=_tainted_read, action=detected_spectre_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_tainted_write, action=detected_spectre_write)
        state.inspect.b('exit', when=angr.BP_BEFORE, condition=_tainted_branch, action=detected_spectre_branch)

        state.memory.read_strategies.insert(0, TargetedStrategy(self.secretIntervals))
        state.memory.write_strategies.insert(0, TargetedStrategy(self.secretIntervals))
        state.inspect.b('address_concretization', when=angr.BP_AFTER, condition=concretization_succeeded, action=log_concretization)

        state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)

        secretStart = 0x1100000  # a should-be-unused part of the virtual memory space, after where CLE puts its 'externs' object
        for (mn,mx) in self.secretIntervals:
            if isAst(mn):
                if state.solver.solution(mn, secretStart):
                    mn_as_int = secretStart
                    state.solver.add(mn == mn_as_int)
                    length = state.solver.eval_one(mx-mn_as_int)  # should be only one possible value of that expression, under these constraints
                    if length is None:
                        raise ValueError("Expected one solution for {} but got these: {}".format(mx-mn_as_int, state.solver.eval(mx-mn_as_int)))
                    mx_as_int = secretStart+length
                    state.solver.add(mx == mx_as_int)
                    secretStart += length
                else:
                    raise ValueError("Can't resolve secret address {} to desired value {}".format(mn, secretStart))
            else:
                mn_as_int = mn
                mx_as_int = mx  # assume that if mn is not an AST, mx isn't either
            for i in range(mn_as_int,mx_as_int):
                state.mem[i].uint8_t = oob_memory_fill("secret", 8, state)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed

# Call during a breakpoint callback on 'mem_read'
def _tainted_read(state):
    addr = state.inspect.mem_read_address
    expr = state.inspect.mem_read_expr
    l.debug("read {} from {} {}".format(describeAst(state,expr), describeAst(state,addr), "which could resolve to a secret address" if _can_point_to_secret(state,addr) else ""))
    if is_tainted(state, addr):
        if isinstance(state.spectre, SpectreExplicitState):
            #return _can_point_to_secret(state, addr)
            return True
        elif isinstance(state.spectre, SpectreOOBState):
            #return can_be_oob(state, addr, state.inspect.mem_read_length)
            return True
        else:
            assert False == "_tainted_read: Unknown state.spectre plugin"
    else:
        return False

# Call during a breakpoint callback on 'mem_write'
def _tainted_write(state):
    addr = state.inspect.mem_write_address
    expr = state.inspect.mem_write_expr
    l.debug("wrote {} to {} {}".format(describeAst(state,expr), describeAst(state,addr), "which could resolve to a secret address" if _can_point_to_secret(state,addr) else ""))
    if is_tainted(state, addr):
        if isinstance(state.spectre, SpectreExplicitState):
            #return _can_point_to_secret(state, addr)
            return True
        elif isinstance(state.spectre, SpectreOOBState):
            #return can_be_oob(state, addr, state.inspect.mem_write_length)
            return True
        else:
            assert False == "_tainted_write: Unknown state.spectre plugin"
    else:
        return False

# Call during a breakpoint callback on 'exit' (i.e. conditional branch)
def _tainted_branch(state):
    return is_tainted(state, state.inspect.exit_guard)

# Can the given ast resolve to an address that points to secret memory
def _can_point_to_secret(state, ast):
    if not isinstance(state.spectre, SpectreExplicitState): return False
    in_each_interval = [claripy.And(ast >= mn, ast < mx) for (mn,mx) in state.spectre.secretIntervals]
    if state.solver.satisfiable(extra_constraints=[claripy.Or(*in_each_interval)]): return True  # there is a solution to current constraints such that the ast points to secret
    return False  # ast cannot point to secret

def detected_spectre_read(state):
    print("\n!!!!!!!! UNSAFE READ !!!!!!!!\n  Instruction Address {}\n  Read Address {}\n  Read Value {}\n  args were {}\n  constraints were {}\n".format(
        hex(state.addr),
        describeAst(state, state.inspect.mem_read_address),
        describeAst(state, state.inspect.mem_read_expr),
        state.globals['args'],
        state.solver.constraints))
    state.spectre.violation = (state.addr, state.inspect.mem_read_address, state.inspect.mem_read_expr)

def detected_spectre_write(state):
    print("\n!!!!!!!! UNSAFE WRITE !!!!!!!!\n  Instruction Address {}\n  Write Address {}\n  Write Value {}\n  args were {}\n  constraints were {}\n".format(
        hex(state.addr),
        describeAst(state, state.inspect.mem_write_address),
        describeAst(state, state.inspect.mem_write_expr),
        state.globals['args'],
        state.solver.constraints))
    state.spectre.violation = (state.addr, state.inspect.mem_write_address, state.inspect.mem_write_expr)

def detected_spectre_branch(state):
    print("\n!!!!!!!! UNSAFE BRANCH !!!!!!!!\n  Branch Address {}\n  Branch Target {}\n  Guard {}\n  args were {}\n  constraints were {}\n".format(
        hex(state.addr),
        state.inspect.exit_target,
        describeAst(state, state.inspect.exit_guard),
        state.globals['args'],
        state.solver.constraints))
    state.spectre.violation = (state.addr, state.inspect.exit_target, state.inspect.exit_guard)

class TargetedStrategy(angr.concretization_strategies.SimConcretizationStrategy):
    """
    Concretization strategy which attempts to concretize addresses to some
    targeted interval(s) if possible. See notes on superclass (and its other
    subclasses) for more info on what's happening here.
    """

    def __init__(self, targetedIntervals, **kwargs):
        super().__init__(**kwargs)
        self.targetedIntervals = targetedIntervals

    def concretize(self, memory, addr):
        """
        Attempts to resolve the address to a value in the targeted interval(s)
        if possible. Else, defers to fallback strategies.
        """
        if not self.targetedIntervals: return None
        try:
            constraint = claripy.Or(*[claripy.And(addr >= mn, addr < mx) for (mn,mx) in self.targetedIntervals])
            return [ self._any(memory, addr, extra_constraints=[constraint]) ]
        except angr.errors.SimUnsatError:
            # no solution
            return None

class SpectreViolationFilter(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique (which you can use on your SimulationManager if you want)
    which puts all states with Spectre violations in a special stash 'spectre_violation'
    """
    def __init__(self):
        super().__init__()

    def filter(self, simgr, state, **kwargs):
        if state.spectre.violation: return 'spectre_violation'
        return simgr.filter(state, **kwargs)
