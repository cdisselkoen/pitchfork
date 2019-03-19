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

def funcEntryState(proj, funcname, args):
    """
    Get a state ready to enter the given function, with each argument
        as a fully unconstrained 64-bit value.
    funcname: name of the function to enter
    args: a list of n values, one for each function argument, each of which
        is a triple (name, length, secret) where:
        name: either None, in which case you get a default name 'arg1', 'arg2', etc
            or a custom name to use for the argument BVS
        length: either None (if the respective function argument is not a pointer, or
            if the size should be unconstrained); or
            the size, *in bytes*, of the array/struct the argument points to
        secret: (only used with SpectreExplicitState, and only matters if length is not None)
            whether the data the argument points to is secret (True) or public (False)
    """
    funcaddr = proj.loader.find_symbol(funcname).rebased_addr
    argBVSs = list(claripy.BVS("arg{}".format(i) if name is None else name, 64) for (i, (name, _, _)) in enumerate(args))
    state = proj.factory.call_state(funcaddr, *argBVSs)
    state.globals['args'] = list(zip(args, argBVSs))
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
        state = funcEntryState(proj, funcname, [(None, None, False), (None, None, False)])
    elif s == '09':
        state = funcEntryState(proj, funcname, [(None, None, False), (None, 8, False)])
    elif s == '15':
        state = funcEntryState(proj, funcname, [(None, 8, False)])
    else:
        state = funcEntryState(proj, funcname, [(None, None, False)])
    return (proj, state)

def kocher11(s):
    """
    Pass one of 'gcc', 'ker', of 'sub' to get an angr project and state for
    the Kocher test case '11gcc', '11ker', or '11sub' respectively.
    """
    proj = angr.Project('spectector-clang/11'+s+'.o')
    state = funcEntryState(proj, "victim_function_v11", [(None, None, False)])
    return (proj, state)

def blatantOOB():
    proj = angr.Project('blatantOOB.o')
    state = funcEntryState(proj, "victim_function_v01", 1)
    return (proj, state)

def tweetnacl_crypto_sign():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_sign_ed25519_tweet", [
        ("sm", None, False),  # signed message: Output parameter, buffer of at least size [length m] + 64
        ("smlen", 8, False),  # signed message length: Output parameter where the actual length of sm is written
        ("m", None, False),  # message: unconstrained length
        ("mlen", None, False),  # message length: length of m. Not a pointer.
        ("sk", 64, True),  # secret key: size 64 bytes
    ])
    return (proj, state)

def tweetnacl_crypto_sign_keypair():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_sign_ed25519_tweet_keypair",
        [("pk", 32, False), ("sk", 64, True)])
    return (proj, state)

def tweetnacl_crypto_stream_salsa20():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_stream_salsa20_tweet", [
        ("c", None, False),  # Output parameter, buffer of size clen
        ("clen", None, False),  # length of the 'c' output buffer
        ("n", 8, False),  # nonce, buffer of size crypto_stream_salsa20_tweet_NONCEBYTES
        ("k", 32, True)  # secret key: size 32 bytes
    ])
    return (proj, state)

def tweetnacl_crypto_stream_xsalsa20():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_stream_xsalsa20_tweet", [
        ("c", None, False),  # Output parameter, buffer of size clen
        ("clen", None, False),  # length of 'c' output buffer
        ("n", 24, False),  # nonce, buffer of size crypto_stream_xsalsa20_tweet_NONCEBYTES
        ("k", 32, True)  # secret key: size 32 bytes
    ])
    return (proj, state)

def tweetnacl_crypto_onetimeauth():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_onetimeauth_poly1305_tweet", [
        ("a", 16, False),  # Output parameter, gets authenticator, size crypto_onetimeauth_BYTES
        ("m", None, False),  # message: unconstrained length
        ("mlen", None, False),  # length of message. Not a pointer
        ("k", 32, True)  # secret key: size 32 bytes
    ])
    return (proj, state)

def tweetnacl_crypto_onetimeauth_verify():
    proj = angr.Project('tweetnacl/tweetnacl.o')
    state = funcEntryState(proj, "crypto_onetimeauth_poly1305_tweet_verify", [
        ("a", 16, False),  # authenticator, size crypto_onetimeauth_BYTES
        ("m", None, False),  # message: unconstrained length
        ("mlen", None, False),  # length of message. Not a pointer
        ("k", 32, True)  # secret key: size 32 bytes
    ])
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

def armSpectreExplicitChecks(proj, state):
    args = state.globals['args']
    secretPairs = ((arg,length) for (i,((name,length,secret),arg)) in enumerate(args) if secret)
    secretIntervals = ((arg, arg+length) for (arg,length) in secretPairs)
    state.register_plugin('spectre', SpectreExplicitState(secretIntervals))
    state.spectre.arm(state)
    assert state.spectre.armed()

def makeSpeculative(proj, state, window=1000):
    """
    window: size of speculative window (~ROB) in VEX instructions. TODO make this x86 instructions
    """
    proj.engines.register_plugin('specvex', SimEngineSpecVEX(window))
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

def runTweetNaclCryptoSign(spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running TweetNaCl crypto_sign {} speculative execution".format("with" if spec else "without"))
    proj,state = tweetnacl_crypto_sign()
    armSpectreExplicitChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runTweetNaclCryptoSignKeypair(spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running TweetNaCl crypto_sign_keypair {} speculative execution".format("with" if spec else "without"))
    proj,state = tweetnacl_crypto_sign_keypair()
    armSpectreExplicitChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runTweetNaclCryptoStreamSalsa20(spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running TweetNaCl crypto_stream_salsa20 {} speculative execution".format("with" if spec else "without"))
    proj,state = tweetnacl_crypto_stream_salsa20()
    armSpectreExplicitChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runTweetNaclCryptoStreamXSalsa20(spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running TweetNaCl crypto_stream_xsalsa20 {} speculative execution".format("with" if spec else "without"))
    proj,state = tweetnacl_crypto_stream_xsalsa20()
    armSpectreExplicitChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runTweetNaclCryptoOnetimeauth(spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running TweetNaCl crypto_onetimeauth {} speculative execution".format("with" if spec else "without"))
    proj,state = tweetnacl_crypto_onetimeauth()
    armSpectreExplicitChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runTweetNaclCryptoOnetimeauthVerify(spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running TweetNaCl crypto_onetimeauth_verify {} speculative execution".format("with" if spec else "without"))
    proj,state = tweetnacl_crypto_onetimeauth_verify()
    armSpectreExplicitChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runKocher(s, spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running Kocher test case {} {} speculative execution".format(s, "with" if spec else "without"))
    proj,state = kocher(s)
    armSpectreOOBChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runKocher11(s, spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in VEX instructions. None (the default) to use default value
    """
    l.info("Running Kocher test case 11{} {} speculative execution".format(s, "with" if spec else "without"))
    proj,state = kocher11(s)
    armSpectreOOBChecks(proj,state)
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    return runState(proj,state)

def runallTweetNacl(spec=True, window=None):
    return { "crypto_sign":runTweetNaclCryptoSign(spec=spec, window=window),
             "crypto_sign_keypair":runTweetNaclCryptoSignKeypair(spec=spec, window=window),
             "crypto_stream_salsa20":runTweetNaclCryptoStreamSalsa20(spec=spec, window=window if window is not None else 100),  # different default due to long runtimes with default window size
             "crypto_stream_xsalsa20":runTweetNaclCryptoStreamXSalsa20(spec=spec, window=window),
             "crypto_onetimeauth":runTweetNaclCryptoOnetimeauth(spec=spec, window=window if window is not None else 500),  # different default due to long runtimes with default window size
             "crypto_onetimeauth_verify":runTweetNaclCryptoOnetimeauthVerify(spec=spec, window=window if window is not None else 500)  # different default due to long runtimes with default window size
           }

def runallKocher(spec=True, window=None):
    return unionDicts(
        # if '05' is immediately after either '04' or '06' here, it fails (detects a
        #   violation even with spec=False).
        # if it is immediately after '03', or if you runKocher('05', spec=False) alone, it
        #   passes (no violation with spec=False). I haven't tested other cases.
        # '07' is exactly the same way: fails (detects a violation even with spec=False)
        #   when immediately after '04' or '06', passes when immediately after '05' or
        #   when run alone.
        # I haven't debugged this yet. I don't currently know of any reason this
        #   should be, i.e. any state that could persist across runKocher() calls.
        # (wishing for a language like Haskell or Rust where functions can't have
        #   arbitrary global side effects and we can't have hidden global mutable state)
        {s:runKocher(s, spec=spec, window=window) for s in ['01','02','03','05','07','04','06','08','09','10','12','13','14','15']},
        {('11'+s):runKocher11(s, spec=spec, window=window) for s in ['gcc','ker','sub']})

def alltests():
    logging.getLogger('angr.engines').setLevel(logging.WARNING)
    logging.getLogger('specvex').setLevel(logging.WARNING)
    logging.getLogger('spectre').setLevel(logging.WARNING)
    logging.getLogger('oob').setLevel(logging.WARNING)
    notspec = runallKocher(spec=False)
    spec = runallKocher(spec=True)
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
