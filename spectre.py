import angr
import claripy

from oob import OOBStrategy, can_be_oob, concretization_succeeded, log_concretization
from taint import taintedUnconstrainedBits, is_tainted
from utils import isAst, describeAst
from abstractdata import AbstractValue, AbstractPointer

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
    This plugin treats some particular range(s) of memory addresses as secret,
        and everything else as public.
    Useful to e.g. determine if a Spectre gadget exists that can leak the secret
        cryptographic key stored in a particular location.

    This plugin does not rely on the OOB state plugin in any way.
    """

    def __init__(self, vars=[], secretIntervals=[], armed=False):
        """
        vars: Iterable of pairs (variable, AbstractValue) where the AbstractValue describes
            what parts of that variable and/or the memory it points to should be considered 'secret'.
            variable can be a concrete address or a BVS.
        secretIntervals: Iterable of pairs (startaddr, endaddr) of memory addresses
            denoting ranges of memory which should also be considered 'secret'.
            Both startaddr and endaddr can be either concrete addresses or BVS's.
            startaddr is inclusive, endaddr is exclusive.
        armed: whether arm() has been called. Leave as False unless you're the copy constructor.

        Everything in memory is considered public by default except whatever is specified by
            `vars` and/or `secretIntervals`.
        """
        super().__init__()
        self.vars = vars
        self._armed = armed
        self.secretIntervals = secretIntervals
        self.violation = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpectreExplicitState(vars=self.vars, secretIntervals=self.secretIntervals, armed=self._armed)

    def arm(self, state):
        """
        Setup hooks and breakpoints to perform Spectre gadget vulnerability detection.
        Also set up concretization to ensure addresses always point to secret data when possible.
        """
        if self._armed:
            l.warn("called arm() on already-armed SpectreExplicitState")
            return

        state.inspect.b('mem_read',  when=angr.BP_AFTER, condition=_tainted_read, action=detected_spectre_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_tainted_write, action=detected_spectre_write)
        state.inspect.b('exit', when=angr.BP_BEFORE, condition=_tainted_branch, action=detected_spectre_branch)

        state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)

        for (var, val) in self.vars:
            assert isAst(var)
            assert isinstance(val, AbstractValue)
            if val.secret:
                raise ValueError("not implemented yet: secret arguments passed by value")
            elif isinstance(val, AbstractPointer):
                self.secretIntervals.extend(intervalsForPointee(var, val.pointee))

        secretStart = 0x1100000  # a should-be-unused part of the virtual memory space, after where CLE puts its 'externs' object
        for (mn,mx) in self.secretIntervals:
            if isAst(mn):
                if state.solver.solution(mn, secretStart):
                    mn_as_int = secretStart
                    state.solver.add(mn == mn_as_int)
                    length = state.solver.eval_one(mx-mn_as_int)  # should be only one possible value of that expression, under these constraints
                    if length is None:
                        raise ValueError("Expected one solution for {} but got these: {}".format(mx-mn_as_int, state.solver.eval(mx-mn_as_int)))
                    mx_as_int = mn_as_int+length
                    state.solver.add(mx == mx_as_int)
                    secretStart += length
                else:
                    raise ValueError("Can't resolve secret address {} to desired value {}".format(mn, secretStart))
            elif isAst(mx):
                raise ValueError("not implemented yet: interval min {} is concrete but max {} is symbolic".format(mn, mx))
            else:
                mn_as_int = mn
                mx_as_int = mx
            for i in range(mn_as_int,mx_as_int):
                state.mem[i].uint8_t = oob_memory_fill("secret", 8, state)

        state.memory.read_strategies.insert(0, TargetedStrategy(self.secretIntervals))
        state.memory.write_strategies.insert(0, TargetedStrategy(self.secretIntervals))
        #state.inspect.b('address_concretization', when=angr.BP_AFTER, condition=concretization_succeeded, action=log_concretization)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed

def intervalsForPointee(var, pointee):
    """
    var: BVS or concrete address
    pointee: AbstractValue or list of AbstractValues at that address
    returns: list of intervals [min, max) describing secret memory locations
    """
    if isinstance(pointee, list):
        # val is a pointer to array or struct
        assert all(isinstance(v, AbstractValue) for v in pointee)
        if all(v.secret for v in pointee):
            return [(var, var+8*len(pointee))]  # everything in that interval is secret
        elif all(not v.secret for v in pointee):
            if any(isinstance(v, AbstractPointer) for v in pointee):
                raise ValueError("not implemented yet: pointer to struct or array containing pointers")
            else:
                pass  # everything in here is a public value, and we have no more pointers to traverse
        else:
            raise ValueError("not implemented yet: pointers to mixed public-and-secret data")
    elif isinstance(pointee, AbstractPointer):
        raise ValueError("not implemented yet: pointer to pointer")
    elif isinstance(pointee, AbstractValue):  # all cases of AbstractValue other than AbstractPointer
        if pointee.secret:
            return [(var, var+8)]  # single 8-byte secret value
    else:
        raise ValueError("pointee {} not a list or AbstractValue".format(pointee))

# Call during a breakpoint callback on 'mem_read'
def _tainted_read(state):
    addr = state.inspect.mem_read_address
    #expr = state.inspect.mem_read_expr
    #l.debug("read {} (with leaf_asts {}) from {} (with leaf_asts {})".format(
        #describeAst(expr),
        #list(describeAst(leaf) for leaf in expr.leaf_asts()),
        #describeAst(addr),
        #list(describeAst(leaf) for leaf in addr.leaf_asts())))
    return is_tainted(addr)

# Call during a breakpoint callback on 'mem_write'
def _tainted_write(state):
    addr = state.inspect.mem_write_address
    #expr = state.inspect.mem_write_expr
    #l.debug("wrote {} (with leaf_asts {}) to {} (with leaf_asts {})".format(
        #describeAst(expr),
        #list(describeAst(leaf) for leaf in expr.leaf_asts()),
        #describeAst(addr),
        #list(describeAst(leaf) for leaf in addr.leaf_asts())))
    return is_tainted(addr)

# Call during a breakpoint callback on 'exit' (i.e. conditional branch)
def _tainted_branch(state):
    guard = state.inspect.exit_guard
    return is_tainted(guard) and \
        state.solver.satisfiable(extra_constraints=[guard == True]) and \
        state.solver.satisfiable(extra_constraints=[guard == False])

# Can the given ast resolve to an address that points to secret memory
def _can_point_to_secret(state, ast):
    if not isinstance(state.spectre, SpectreExplicitState): return False
    in_each_interval = [claripy.And(ast >= mn, ast < mx) for (mn,mx) in state.spectre.secretIntervals]
    if state.solver.satisfiable(extra_constraints=[claripy.Or(*in_each_interval)]): return True  # there is a solution to current constraints such that the ast points to secret
    return False  # ast cannot point to secret

def detected_spectre_read(state):
    print("\n!!!!!!!! UNSAFE READ !!!!!!!!\n  Instruction Address {}\n  Read Address {}\n  Read Value {}\n  args were {}\n  constraints were {}\n".format(
        hex(state.addr),
        describeAst(state.inspect.mem_read_address),
        describeAst(state.inspect.mem_read_expr),
        state.globals['args'],
        state.solver.constraints))
    state.spectre.violation = ('read', state.addr, state.inspect.mem_read_address, state.inspect.mem_read_expr)

def detected_spectre_write(state):
    print("\n!!!!!!!! UNSAFE WRITE !!!!!!!!\n  Instruction Address {}\n  Write Address {}\n  Write Value {}\n  args were {}\n  constraints were {}\n".format(
        hex(state.addr),
        describeAst(state.inspect.mem_write_address),
        describeAst(state.inspect.mem_write_expr),
        state.globals['args'],
        state.solver.constraints))
    state.spectre.violation = ('write', state.addr, state.inspect.mem_write_address, state.inspect.mem_write_expr)

def detected_spectre_branch(state):
    print("\n!!!!!!!! UNSAFE BRANCH !!!!!!!!\n  Branch Address {}\n  Branch Target {}\n  Guard {}\n  args were {}\n  constraints were {}\n".format(
        hex(state.addr),
        state.inspect.exit_target,
        describeAst(state.inspect.exit_guard),
        state.globals['args'],
        state.solver.constraints))
    state.spectre.violation = ('branch', state.addr, state.inspect.exit_target, state.inspect.exit_guard)

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
