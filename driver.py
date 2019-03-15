from specvex import SimEngineSpecVEX, SpecState
from oob import OOBState
from spectre import SpectreOOBState, SpectreExplicitState

import angr
import claripy
import monkeyhex
import logging
l = logging.getLogger(name=__name__)

logging.getLogger('angr.engines').setLevel(logging.INFO)
#logging.getLogger('angr.engines.vex.expressions').setLevel(logging.INFO)
#logging.getLogger('angr.engines.unicorn').setLevel(logging.INFO)
#logging.getLogger('angr.engines.hook').setLevel(logging.INFO)
logging.getLogger('specvex').setLevel(logging.DEBUG)
logging.getLogger('spectre').setLevel(logging.INFO)
logging.getLogger('oob').setLevel(logging.DEBUG)
logging.getLogger(__name__).setLevel(logging.INFO)

def funcEntryState(proj, funcname, n, arglengths=None, argnames=None):
    """
    Get a state ready to enter the given function, with each argument
        as a fully unconstrained 64-bit value.
    funcname: name of the function to enter
    n: number of arguments to the function
    arglengths: an iterable of n values, each of which is either:
        None (if the respective function argument is not a pointer, or if the size should be unconstrained); or
        the size, in *bytes*, of the array/struct the argument points to.
        If arglengths itself is None (the default), that is shorthand for all None's
    argnames: either None (the default) in which case the argument BVS's get
        names 'arg1', 'arg2', etc, or an iterable of custom names to use for
        the argument BVS's
    """
    funcaddr = proj.loader.find_symbol(funcname).rebased_addr
    args = list(claripy.BVS("arg{}".format(i) if argnames is None else argnames[i], 64) for i in range(n))
    state = proj.factory.call_state(funcaddr, *args)
    state.globals['args'] = list(zip(args, arglengths) if arglengths is not None else zip(args, iter(lambda _: None, True)))
    return state

# Loading various binaries for testing

def fauxware():
    proj = angr.Project('../angr-binaries/tests/x86_64/fauxware')
    state = proj.factory.entry_state()
    return (proj, state)

def kocher(s):
    """
    Pass a string like "01" or "12" to get an angr project and state for that
    Kocher test case.
    """
    proj = angr.Project('spectector-clang/'+s+'.o')
    funcname = "victim_function_v"+s
    if s in ('10','12'):
        state = funcEntryState(proj, funcname, 2)
    elif s == '09':
        state = funcEntryState(proj, funcname, 2, arglengths=[None, 8])
    elif s == '15':
        state = funcEntryState(proj, funcname, 1, arglengths=[8])
    else:
        state = funcEntryState(proj, funcname, 1)
    return (proj, state)

def kocher11(s):
    """
    Pass one of 'gcc', 'ker', of 'sub' to get an angr project and state for
    the Kocher test case '11gcc', '11ker', or '11sub' respectively.
    """
    proj = angr.Project('spectector-clang/11'+s+'.o')
    state = funcEntryState(proj, "victim_function_v11", 1)
    return (proj, state)

def blatantOOB():
    proj = angr.Project('blatantOOB.o')
    state = funcEntryState(proj, "victim_function_v01", 1)
    return (proj, state)

def tweetnacl_crypto_sign():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_sign_ed25519_tweet", 5,
        argnames=["sm","smlen","m","mlen","sk"],
        arglengths=[None, # sm (signed message): Output parameter, buffer of at least size [length m] + 64
                    8, # smlen (signed message length): Output parameter where the actual length of sm is written
                    None, # m (message): unconstrained
                    None, # mlen (message length): length of m
                    64] # sk (secret key) size 64 bytes
    )
    return (proj, state)

# Set up checking

def armBoundsChecks(proj,state):
    state.register_plugin('oob', OOBState(proj))
    assert len(state.oob.inbounds_intervals) > 0
    state.oob.arm(state)
    assert state.oob.armed()

def armSpectreOOBChecks(proj,state):
    state.register_plugin('oob', OOBState(proj))
    state.register_plugin('spectre', SpectreOOBState())
    state.spectre.arm(state)
    assert state.spectre.armed()

def armSpectreExplicitChecks(proj, state, secretArgs):
    """
    secretArgs: an iterable of booleans, indicate for each arg whether the arg is secret (True) or public (False)
    """
    args = state.globals['args']
    secretPairs = (args[i] for (i,arg) in enumerate(secretArgs) if arg)
    secretIntervals = ((arg, arg+length) for (arg,length) in secretPairs)
    state.register_plugin('spectre', SpectreExplicitState(secretIntervals))
    state.spectre.arm(state)
    assert state.spectre.armed()

def makeSpeculative(proj, state):
    proj.engines.register_plugin('specvex', SimEngineSpecVEX(1000))
    proj.engines.order = ['specvex' if x=='vex' else x for x in proj.engines.order]  # replace 'vex' with 'specvex'
    if proj.engines.has_plugin('vex'): proj.engines.release_plugin('vex')

    #state.options.discard(angr.options.LAZY_SOLVES)  # turns out LAZY_SOLVES is not on by default
    state.register_plugin('spec', SpecState())
    assert state.spec.ins_executed == 0

def runState(proj, state):
    simgr = proj.factory.simgr(state, save_unsat=True)
    if state.has_plugin('oob'):
        simgr.use_technique(OOBViolationFilter())
    if state.has_plugin('spectre'):
        simgr.use_technique(SpectreViolationFilter())
    simgr.run()
    return simgr

class OOBViolationFilter(angr.exploration_techniques.ExplorationTechnique):
  def __init__(self):
    super().__init__()

  def filter(self, simgr, state, **kwargs):
    if state.oob.violation: return 'oob_violation'
    return simgr.filter(state, **kwargs)

class SpectreViolationFilter(angr.exploration_techniques.ExplorationTechnique):
  def __init__(self):
    super().__init__()

  def filter(self, simgr, state, **kwargs):
    if state.spectre.violation: return 'spectre_violation'
    return simgr.filter(state, **kwargs)

# useful utility for interactive mode
def showbbASM(proj, bbaddr):
    proj.factory.block(bbaddr).capstone.pp()

# useful utility for interactive mode
def showbbVEX(proj, bbaddr):
    proj.factory.block(bbaddr).vex.pp()

def runTweetNaclSpec():
    l.info("Running TweetNaCl crypto_sign with speculative execution")
    proj,state = tweetnacl_crypto_sign()
    armSpectreExplicitChecks(proj, state, [False, False, False, False, True])
    makeSpeculative(proj,state)
    return runState(proj,state)

def runTweetNaclNotSpec():
    l.info("Running TweetNaCl crypto_sign without speculative exeuction")
    proj,state = tweetnacl_crypto_sign()
    armSpectreExplicitChecks(proj, state, [False, False, False, False, True])
    return runState(proj,state)

def runSpec(s):
    l.info("Running Kocher test case {} with speculative execution".format(s))
    proj,state = kocher(s)
    armSpectreOOBChecks(proj,state)
    makeSpeculative(proj,state)
    return runState(proj,state)

def runNotSpec(s):
    l.info("Running Kocher test case {} without speculative execution".format(s))
    proj,state = kocher(s)
    armSpectreOOBChecks(proj,state)
    return runState(proj,state)

def run11Spec(s):
    l.info("Running Kocher test case 11{} with speculative execution".format(s))
    proj,state = kocher11(s)
    armSpectreOOBChecks(proj,state)
    makeSpeculative(proj,state)
    return runState(proj,state)

def run11NotSpec(s):
    l.info("Running Kocher test case 11{} without speculative execution".format(s))
    proj,state = kocher11(s)
    armSpectreOOBChecks(proj,state)
    return runState(proj,state)

def runallSpec():
    return unionDicts(
        {s:runSpec(s) for s in ['01','02','03','04','05','06','07','08','09','10','12','13','14','15']},
        {('11'+s):run11Spec(s) for s in ['gcc','ker','sub']})

def runallNotSpec():
    return unionDicts(
        # if '05' is immediately after either '04' or '06' here, it fails (detects a
        #   violation).
        # if it is immediately after '03', or if you runNotSpec('05') alone, it
        #   passes (no violation). I haven't tested other cases.
        # '07' is exactly the same way: fails (detects a violation) when immediately
        #   after '04' or '06', passes (no violation) when immediately after '05' or
        #   when run alone.
        # I haven't debugged this yet. I don't currently know of any reason this
        #   should be, i.e. any state that could persist across runNotSpec() calls.
        # (wishing for a language like Haskell or Rust where functions can't have
        #   arbitrary global side effects and we can't have hidden global mutable state)
        {s:runNotSpec(s) for s in ['01','02','03','05','07','04','06','08','09','10','12','13','14','15']},
        {('11'+s):run11NotSpec(s) for s in ['gcc','ker','sub']})

def alltests():
    logging.getLogger('angr.engines').setLevel(logging.WARNING)
    logging.getLogger('specvex').setLevel(logging.WARNING)
    logging.getLogger('spectre').setLevel(logging.WARNING)
    logging.getLogger('oob').setLevel(logging.WARNING)
    notspec = runallNotSpec()
    spec = runallSpec()
    def violationDetected(simgr):
        return 'spectre_violation' in simgr.stashes and len(simgr.spectre_violation) > 0
    def testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(notspec[s])
            else "FAIL: no violation detected" if not violationDetected(spec[s])
            else "PASS")
    return {k:testResult(k) for k in spec.keys()}

def unionDicts(dicta, dictb):
    return {**dicta, **dictb}  # requires Python 3.5+

if __name__ == '__main__':
    from pprint import pprint
    pprint(alltests())
