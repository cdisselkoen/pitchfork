import angr
import claripy

from oob import OOBStrategy, OOBState, can_be_oob, concretization_succeeded, log_concretization
from taint import taintedUnconstrainedBits, is_tainted
from utils import isAst, describeAst, isDefinitelyEqual
from abstractdata import AbstractValue, AbstractPointer, AbstractPointerToUnconstrainedPublic

import logging
l = logging.getLogger(name=__name__)

def armSpectreOOBChecks(proj,state):
    state.register_plugin('oob', OOBState(proj))
    state.register_plugin('spectre', SpectreOOBState())
    state.spectre.arm(state)
    assert state.spectre.armed()

def armSpectreExplicitChecks(proj, state):
    args = state.globals['args']
    otherSecrets = state.globals['otherSecrets'] if 'otherSecrets' in state.globals else []
    state.register_plugin('spectre', SpectreExplicitState(vars=args.values(), secretIntervals=otherSecrets))
    state.spectre.arm(state)
    assert state.spectre.armed()

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

        secretStart = 0x1100000  # a should-be-unused part of the virtual memory space, after where CLE puts its 'externs' object
        secretMustEnd = 0x2000000  # secrets must be stored somewhere in [secretStart, secretMustEnd)

        notSecretAddresses = []  # see notes in MemoryLayout.__init__
        for (var, val) in self.vars:
            assert isAst(var)
            assert isinstance(val, AbstractValue)
            if val.value is not None: state.add_constraints(var == val.value)
            if val.secret:
                raise ValueError("not implemented yet: secret arguments passed by value")
            elif isinstance(val, AbstractPointer):
                if val.cannotPointSecret: notSecretAddresses.append(var)
                (mlayout, newStart) = memLayoutForPointee(var, val.pointee, secretStart, secretMustEnd)
                secretStart = newStart  # update to account for what was used in the call to memLayoutForPointee
                self.secretIntervals.extend(mlayout.secretIntervals)
                notSecretAddresses.extend(mlayout.notSecretAddresses)
                for (a, (v, bits)) in mlayout.concreteAssignments.items():
                    #print("Assigning address {} to value {}, {} bits".format(describeAst(a), describeAst(v), bits))
                    if bits == 8: state.mem[a].uint8_t = v
                    elif bits == 16: state.mem[a].uint16_t = v
                    elif bits == 32: state.mem[a].uint32_t = v
                    elif bits == 64: state.mem[a].uint64_t = v
                    else: raise ValueError("unexpected bitlength: {}".format(bits))
            elif isinstance(val, AbstractPointerToUnconstrainedPublic):
                if val.cannotPointSecret: notSecretAddresses.append(var)
            #print("Secret intervals:")
            #for (mn, mx) in self.secretIntervals:
                #print("[{}, {})".format(describeAst(mn), describeAst(mx)))
            #print("Not-secret addresses:")
            #for addr in notSecretAddresses:
                #print(describeAst(addr))

        self.secretIntervals = normalizeIntervals(self.secretIntervals)

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

        for addr in notSecretAddresses:
            state.solver.add(claripy.And(*[claripy.Or(addr < mn, addr >= mx) for (mn,mx) in self.secretIntervals]))

        state.memory.read_strategies.insert(0, TargetedStrategy(self.secretIntervals))
        state.memory.write_strategies.insert(0, TargetedStrategy(self.secretIntervals))
        #state.inspect.b('address_concretization', when=angr.BP_AFTER, condition=concretization_succeeded, action=log_concretization)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed

class MemoryLayout:
    """
    Information about which memory addresses contain secret data,
        and/or should contain given concrete public data
    """
    def __init__(self):
        self.secretIntervals = []  # Intervals [min, max) describing secret memory locations. min is inclusive, max exclusive. Can be concrete or symbolic.
        self.concreteAssignments = {}  # Keys are concrete addresses, values are pairs (val, bits) where 'val' is the value (concrete or symbolic) to be stored at that location, and 'bits' is the bitlength of 'val'
        self.notSecretAddresses = []  # Addresses (probably symbolic) which we assert _cannot_ point (directly) to any secret data, even by aliasing with a pointer to secret data

    def addSecretInterval(self, mn, mx):
        """
        Mark the interval [mn, mx) as containing secret data. min and max are (concrete or symbolic) addresses
        """
        self.secretIntervals.append((mn, mx))

    def assign(self, addr, val, bits):
        """
        Assign the memory at (concrete) 'addr' to have the (concrete or symbolic) 'val' with bitlength 'bits'
        """
        self.concreteAssignments[addr] = (val, bits)

    def addNotSecretAddress(self, addr):
        self.notSecretAddresses.append(addr)

    def mergeWith(self, otherMemoryLayout):
        """
        Incorporate all the information from otherMemoryLayout into this one
        """
        self.secretIntervals.extend(otherMemoryLayout.secretIntervals)
        self.concreteAssignments.update(otherMemoryLayout.concreteAssignments)
        self.notSecretAddresses.extend(otherMemoryLayout.notSecretAddresses)

    def display(self):
        """
        Return a string describing the MemoryLayout in detail
        """
        r = "\nSecret intervals:"
        for (mn, mx) in self.secretIntervals:
            r += "\n[{}, {})".format(describeAst(mn), describeAst(mx))
        r += "\nAssignments:"
        for (a, (v, bits)) in self.concreteAssignments.items():
            r += "\nAddress {} gets value {}, {} bits".format(describeAst(a), describeAst(v), bits)
        r += "\nNot-secret addresses:"
        for addr in self.notSecretAddresses:
            r += "\n{}".format(describeAst(addr))
        return r

def memLayoutForPointee(var, pointee, scratchStart, scratchEnd):
    """
    var: BVS or concrete address
    pointee: AbstractValue or list of AbstractValues at that address
    scratchStart, scratchEnd: Concrete addresses describing an available place in memroy where to lay out the data
    returns: MemoryLayout for the given pointee, and a new value for scratchStart (pointing to where is still free to use as scratch)
    """
    mlayout = MemoryLayout()
    if isinstance(pointee, AbstractValue):
        pointee = [pointee]  # treat pointer-to-value like pointer-to-array-length-1.  Reduces code duplication
    if isinstance(pointee, list):
        # val is a pointer to array or struct
        assert all(isinstance(v, AbstractValue) for v in pointee)
        if all(v.secret for v in pointee):
            totalBitLength = sum(v.bits for v in pointee)
            mlayout.addSecretInterval(var, var + (totalBitLength // 8))  # everything in that interval is secret
            # we don't bother checking for v.value for secret v, since it doesn't matter to the analysis
        else:
            bytesSoFar = 0
            for v in pointee:
                elementaddr = var + bytesSoFar
                if v.secret:
                    mlayout.addSecretInterval(elementaddr, elementaddr + (v.bits // 8))  # single secret value
                    # we don't bother checking for v.value for secret v, since it doesn't matter to the analysis
                elif isinstance(v, AbstractPointer):
                    # v is a pointer, that lives in memory at elementaddr
                    vaddr = v.value if v.value is not None else scratchStart  # we decide that v's value is this
                    mlayout.assign(elementaddr, vaddr, v.bits)  # at elementaddr, we have the value (that is, pointer/address) vaddr
                    scratchStart += v.maxPointeeSize  # reserve this scratch for the data v points to
                    if v.cannotPointSecret: mlayout.addNotSecretAddress(vaddr)
                    (pointeeLayout, newScratchStart) = memLayoutForPointee(vaddr, v.pointee, scratchStart, scratchEnd)
                    scratchStart = newScratchStart
                    mlayout.mergeWith(pointeeLayout)
                elif isinstance(v, AbstractPointerToUnconstrainedPublic):
                    if v.cannotPointSecret or v.value is not None:  # these are the two cases where we must actually allocate
                        vaddr = v.value if v.value is not None else scratchStart  # we decide that v's value is this
                        mlayout.assign(elementaddr, vaddr, v.bits)  # at elementaddr, we have the value (that is, pointer/address) vaddr
                        scratchStart += v.maxPointeeSize  # reserve this scratch for the data v points to
                        if v.cannotPointSecret: mlayout.addNotSecretAddress(vaddr)
                else:
                    if v.value is not None: mlayout.assign(elementaddr, v.value, v.bits)
                bytesSoFar += v.bits // 8  # advance to the next element
    else:
        raise ValueError("pointee {} not a list or AbstractValue".format(pointee))
    return (mlayout, scratchStart)

def normalizeIntervals(intervals):
    """
    Given a list of [min, max) intervals,
        - sort them in increasing order, and
        - collapse contiguous intervals into a single larger interval
    returns: new list of intervals
    """
    assert isinstance(intervals, list)
    intervals.sort(key=lambda pair: -1 if (isAst(pair[0]) or isAst(pair[1])) else pair[0])  # sort all symbolic intervals to beginning, otherwise sort by low coordinate
    newIntervals = []
    while intervals:
        interval = intervals.pop()  # gets the interval with largest max
        if intervals:
            prevInterval = intervals[-1]  # the interval before that
            while isDefinitelyEqual(prevInterval[1], interval[0]):  # this interval is contiguous with the previous interval
                intervals.pop()  # remove prevInterval
                interval[0] = prevInterval[0]  # `interval` now covers the entire range
                if not intervals: break  # no intervals left
                prevInterval = intervals[-1]  # now compare with the interval before _that_
            # not contiguous with the previous interval
        newIntervals.append(interval)
    return newIntervals

# Call during a breakpoint callback on 'mem_read'
def _tainted_read(state):
    addr = state.inspect.mem_read_address
    #expr = state.inspect.mem_read_expr
    #l.debug("read {} (with leaf_asts {}) from {} (with leaf_asts {})".format(
        #describeAst(expr),
        #list(describeAst(leaf) for leaf in expr.leaf_asts()),
        #describeAst(addr),
        #list(describeAst(leaf) for leaf in addr.leaf_asts())))
    return isAst(addr) and is_tainted(addr)

# Call during a breakpoint callback on 'mem_write'
def _tainted_write(state):
    addr = state.inspect.mem_write_address
    #expr = state.inspect.mem_write_expr
    #l.debug("wrote {} (with leaf_asts {}) to {} (with leaf_asts {})".format(
        #describeAst(expr),
        #list(describeAst(leaf) for leaf in expr.leaf_asts()),
        #describeAst(addr),
        #list(describeAst(leaf) for leaf in addr.leaf_asts())))
    return isAst(addr) and is_tainted(addr)

# Call during a breakpoint callback on 'exit' (i.e. conditional branch)
def _tainted_branch(state):
    guard = state.inspect.exit_guard
    return isAst(guard) and is_tainted(guard) and \
        state.solver.satisfiable(extra_constraints=[guard == True]) and \
        state.solver.satisfiable(extra_constraints=[guard == False])

# Can the given ast resolve to an address that points to secret memory
def _can_point_to_secret(state, ast):
    if not isinstance(state.spectre, SpectreExplicitState): return False
    in_each_interval = [claripy.And(ast >= mn, ast < mx) for (mn,mx) in state.spectre.secretIntervals]
    if state.solver.satisfiable(extra_constraints=[claripy.Or(*in_each_interval)]): return True  # there is a solution to current constraints such that the ast points to secret
    return False  # ast cannot point to secret

def detected_spectre_read(state):
    print("\n!!!!!!!! UNSAFE READ !!!!!!!!\n  Instruction Address {}\n  Read Address {}\n  Read Value {}\n  A set of argument values meeting constraints is: {}\n  constraints were {}\n".format(
        hex(state.addr),
        describeAst(state.inspect.mem_read_address),
        describeAst(state.inspect.mem_read_expr),
        {name: state.solver.eval(bvs) for (name, (bvs, _)) in state.globals['args'].items()},
        state.solver.constraints))
    state.spectre.violation = ('read', state.addr, state.inspect.mem_read_address, state.inspect.mem_read_expr)

def detected_spectre_write(state):
    print("\n!!!!!!!! UNSAFE WRITE !!!!!!!!\n  Instruction Address {}\n  Write Address {}\n  Write Value {}\n  A set of argument values meeting constraints is: {}\n  constraints were {}\n".format(
        hex(state.addr),
        describeAst(state.inspect.mem_write_address),
        describeAst(state.inspect.mem_write_expr),
        {name: state.solver.eval(bvs) for (name, (bvs, _)) in state.globals['args'].items()},
        state.solver.constraints))
    state.spectre.violation = ('write', state.addr, state.inspect.mem_write_address, state.inspect.mem_write_expr)

def detected_spectre_branch(state):
    print("\n!!!!!!!! UNSAFE BRANCH !!!!!!!!\n  Branch Address {}\n  Branch Target {}\n  Guard {}\n  A set of argument values meeting constraints is: {}\n  constraints were {}\n".format(
        hex(state.addr),
        state.inspect.exit_target,
        describeAst(state.inspect.exit_guard),
        {name: state.solver.eval(bvs) for (name, (bvs, _)) in state.globals['args'].items()},
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
