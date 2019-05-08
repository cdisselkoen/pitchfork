from specvex import SimEngineSpecVEX, SpecState
from oob import OOBState, OOBViolationFilter
from spectre import SpectreOOBState, SpectreExplicitState, SpectreViolationFilter
from taint import taintedUnconstrainedBits
from irop_hook import IROpHook
from utils import *  #pylint:disable=unused-wildcard-import
from abstractdata import publicValue, secretValue, pointerTo, pointerToUnconstrainedPublic, publicArray, secretArray, array, struct

import angr
import claripy
import monkeyhex
import logging
l = logging.getLogger(name=__name__)

import time

#logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.DEBUG)
#logging.getLogger('angr.engines').setLevel(logging.INFO)
#logging.getLogger('specvex').setLevel(logging.DEBUG)
logging.getLogger('spectre').setLevel(logging.INFO)
logging.getLogger('oob').setLevel(logging.DEBUG)
#logging.getLogger('irop_hook').setLevel(logging.DEBUG)
logging.getLogger(__name__).setLevel(logging.INFO)

def funcEntryState(proj, funcname, args):
    """
    Get a state ready to enter the given function, with each argument
        as a fully unconstrained 64-bit value.
    funcname: name of the function to enter
    args: a list of n values, one for each function argument, each of which
        is a pair (name, val) where:
        name: either None, in which case you get a default name 'arg1', 'arg2', etc
            or a custom name to use for the argument BVS
        val: an AbstractValue denoting the structure of the argument
            See notes in abstractdata.py
    """
    funcaddr = proj.loader.find_symbol(funcname).rebased_addr
    argnames = list("arg{}".format(i) if name is None else name for (i, (name, _)) in enumerate(args))
    argBVSs = list(claripy.BVS(name, 64) for name in argnames)
    state = proj.factory.call_state(funcaddr, *argBVSs)
    state.globals['args'] = {argname:(argBVS, val) for (argname, (_, val), argBVS) in zip(argnames, args, argBVSs)}
    state.register_plugin('irop_hook', IROpHook())
    return state

def getArgBVS(state, argname):
    return state.globals['args'][argname][0]

# Loading various binaries for testing

def kocher(s):
    """
    Pass a string like "01" or "12" to get an angr project and state for that
    Kocher test case.
    """
    proj = angr.Project('spectector-clang/'+s+'.o')
    funcname = "victim_function_v"+s
    if s in ('10','12'):
        state = funcEntryState(proj, funcname, [(None, publicValue()), (None, publicValue())])
    elif s == '09':
        state = funcEntryState(proj, funcname, [(None, publicValue()), (None, pointerToUnconstrainedPublic())])
    elif s == '15':
        state = funcEntryState(proj, funcname, [(None, pointerToUnconstrainedPublic())])
    else:
        state = funcEntryState(proj, funcname, [(None, publicValue())])
    return (proj, state)

def kocher11(s):
    """
    Pass one of 'gcc', 'ker', of 'sub' to get an angr project and state for
    the Kocher test case '11gcc', '11ker', or '11sub' respectively.
    """
    proj = angr.Project('spectector-clang/11'+s+'.o')
    state = funcEntryState(proj, "victim_function_v11", [(None, publicValue())])
    return (proj, state)

def blatantOOB():
    proj = angr.Project('blatantOOB.o')
    state = funcEntryState(proj, "victim_function_v01", [(None, publicValue())])
    return (proj, state)

def tweetnaclProject():
    proj = angr.Project('tweetnacl/testbinaryO3')
    makeRandomBytesSecret(proj)
    return proj

def donnaProject():
    return angr.Project('x25519bench/test')

def opensslProject():
    return angr.Project('openssl/openssl')

def tweetnacl_crypto_sign(max_messagelength=256, with_hash_stub=True):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    with_hash_stub: if True, then use a stub for the SHA512 hash function rather than
        trying to analyze it directly
    """
    proj = tweetnaclProject()
    if with_hash_stub: addHashblocksStub(proj)
    state = funcEntryState(proj, "crypto_sign_ed25519_tweet", [
        ("sm", pointerToUnconstrainedPublic()),  # signed message: Output parameter, buffer of at least size [length m] + 64
        ("smlen", pointerTo(publicValue(), 8)),  # signed message length: Output parameter where the actual length of sm is written
        ("m", pointerToUnconstrainedPublic()),  # message: unconstrained length
        ("mlen", publicValue()),  # message length: length of m. Not a pointer.
        ("sk", pointerTo(secretArray(64), 64)),  # secret key: size 64 bytes
    ])
    state.add_constraints(getArgBVS(state, 'mlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_sign_open(max_messagelength=256, with_hash_stub=True):
    """
    note that this function *does not handle any secret inputs* so it probably isn't necessary
        to analyze. Still included for completeness.
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    with_hash_stub: if True, then use a stub for the SHA512 hash function rather than
        trying to analyze it directly
    """
    proj = tweetnaclProject()
    if with_hash_stub: addHashblocksStub(proj)
    state = funcEntryState(proj, "crypto_sign_ed25519_tweet_open", [
        ("m", pointerToUnconstrainedPublic()),  # Output parameter: message, buffer of at least size 'smlen'
        ("mlen", pointerTo(publicValue(), 8)),  # Output parameter where the actual length of m is written
        ("sm", pointerToUnconstrainedPublic()),  # Signed message: length 'smlen'
        ("smlen", publicValue()),  # signed message length: length of 'sm'. Not a pointer.
        ("pk", pointerTo(publicArray(32), 32))  # public key: size crypto_sign_PUBLICKEYBYTES
    ])
    state.add_constraints(getArgBVS(state, 'smlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_sign_keypair(with_hash_stub=True):
    """
    with_hash_stub: if True, then use a stub for the SHA512 hash function rather than
        trying to analyze it directly
    """
    proj = tweetnaclProject()
    if with_hash_stub: addHashblocksStub(proj)
    state = funcEntryState(proj, "crypto_sign_ed25519_tweet_keypair",
        [("pk", pointerTo(publicArray(32), 32)), ("sk", pointerTo(secretArray(64), 64))])
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_hash(max_messagelength=256, with_hashblocks_stub=True):
    """
    note that this function *does not handle any secret inputs* so it probably isn't necessary
        to analyze. Still included for completeness, and because it is a building block of
        some of the other functions that might be useful to test alone.
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    with_hash_stub: if True, then use a stub for the crypto_hashblocks function rather than
        trying to analyze it directly
    """
    proj = tweetnaclProject()
    if with_hashblocks_stub: addHashblocksStub(proj)
    state = funcEntryState(proj, "crypto_hash_sha512_tweet", [
        ("h", pointerTo(publicArray(64), 64)),  # Output parameter: where to put the hash. 64 bytes.
        ("m", pointerToUnconstrainedPublic()),  # message: length 'mlen'
        ("mlen", publicValue())  # message length: length of m. Not a pointer.
    ])
    state.add_constraints(getArgBVS(state, 'mlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_stream_salsa20(max_outputbytes=128):
    """
    crypto_stream_salsa20 produces a continuous stream of output.
    max_outputbytes: maximum value of the 'clen' parameter which determines the output size
        i.e., the symbolic execution will not consider values of 'clen' larger than max_outputbytes
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_stream_salsa20_tweet", [
        ("c", pointerToUnconstrainedPublic()),  # Output parameter, buffer of size clen
        ("clen", publicValue()),  # length of the 'c' output buffer
        ("n", pointerTo(secretArray(8), 8)),  # nonce, buffer of size crypto_stream_salsa20_tweet_NONCEBYTES
        ("k", pointerTo(secretArray(32), 32))  # secret key: size 32 bytes
    ])
    state.add_constraints(getArgBVS(state, 'clen') <= max_outputbytes)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_stream_xsalsa20(max_outputbytes=128):
    """
    crypto_stream_xsalsa20 produces a continuous stream of output.
    max_outputbytes: maximum value of the 'clen' parameter which determines the output size
        i.e., the symbolic execution will not consider values of 'clen' larger than max_outputbytes
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_stream_xsalsa20_tweet", [
        ("c", pointerToUnconstrainedPublic()),  # Output parameter, buffer of size clen
        ("clen", publicValue()),  # length of 'c' output buffer
        ("n", pointerTo(secretArray(24), 24)),  # nonce, buffer of size crypto_stream_xsalsa20_tweet_NONCEBYTES
        ("k", pointerTo(secretArray(32), 32))  # secret key: size 32 bytes
    ])
    state.add_constraints(getArgBVS(state, 'clen') <= max_outputbytes)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_onetimeauth(max_messagelength=256):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_onetimeauth_poly1305_tweet", [
        ("a", pointerTo(publicArray(16), 16)),  # Output parameter, gets authenticator, size crypto_onetimeauth_BYTES
        ("m", pointerToUnconstrainedPublic()),  # message: unconstrained length
        ("mlen", publicValue()),  # length of message. Not a pointer
        ("k", pointerTo(secretArray(32), 32))  # secret key: size 32 bytes
    ])
    state.add_constraints(getArgBVS(state, 'mlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_onetimeauth_verify(max_messagelength=256):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_onetimeauth_poly1305_tweet_verify", [
        ("a", pointerTo(publicArray(16), 16)),  # authenticator, size crypto_onetimeauth_BYTES
        ("m", pointerToUnconstrainedPublic()),  # message: unconstrained length
        ("mlen", publicValue()),  # length of message. Not a pointer
        ("k", pointerTo(secretArray(32), 32))  # secret key: size 32 bytes
    ])
    state.add_constraints(getArgBVS(state, 'mlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_secretbox(max_messagelength=256):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_secretbox_xsalsa20poly1305_tweet", [
        ("c", pointerToUnconstrainedPublic()),  # Output parameter, will hold ciphertext, length 'mlen'
        ("m", pointerToUnconstrainedPublic()),  # message: length 'mlen'
        ("mlen", publicValue()),  # length of message. Not a pointer
        ("n", pointerTo(secretArray(24), 24)),  # nonce, buffer of size crypto_secretbox_NONCEBYTES
        ("k", pointerTo(secretArray(32), 32))  # secret key: size 32 bytes
    ])
    state.add_constraints(getArgBVS(state, 'mlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_secretbox_open(max_messagelength=256):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_secretbox_xsalsa20poly1305_tweet_open", [
        ("m", pointerToUnconstrainedPublic()),  # Output parameter, will hold plaintext, length 'clen'
        ("c", pointerToUnconstrainedPublic()),  # ciphertext, length 'clen'
        ("clen", publicValue()),  # length of ciphertext. Not a pointer
        ("n", pointerTo(secretArray(24), 24)),  # nonce, buffer of size crypto_secretbox_NONCEBYTES
        ("k", pointerTo(secretArray(32), 32))  # secret key: size 32 bytes
    ])
    state.add_constraints(getArgBVS(state, 'clen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_box(max_messagelength=256):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_box_curve25519xsalsa20poly1305_tweet", [
        ("c", pointerToUnconstrainedPublic()),  # Output parameter, will hold ciphertext, length 'mlen'
        ("m", pointerToUnconstrainedPublic()),  # message: length 'mlen'
        ("mlen", publicValue()),  # length of message. Not a pointer
        ("n", pointerTo(secretArray(24), 24)),  # nonce, size crypto_box_NONCEBYTES
        ("pk", pointerTo(publicArray(32), 32)),  # public key, size crypto_box_PUBLICKEYBYTES
        ("sk", pointerTo(secretArray(32), 32))  # secret key, size crypto_box_SECRETKEYBYTES
    ])
    state.add_constraints(getArgBVS(state, 'mlen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def tweetnacl_crypto_box_open(max_messagelength=256):
    """
    max_messagelength: maximum length of the message, in bytes.
        i.e., the symbolic execution will not consider messages longer than max_messagelength
    """
    proj = tweetnaclProject()
    state = funcEntryState(proj, "crypto_box_curve25519xsalsa20poly1305_tweet_open", [
        ("m", pointerToUnconstrainedPublic()),  # Output parameter, will hold plaintext, length 'clen'
        ("c", pointerToUnconstrainedPublic()),  # ciphertext: length 'clen'
        ("clen", publicValue()),  # length of ciphertext. Not a pointer
        ("n", pointerTo(secretArray(24), 24)),  # nonce, size crypto_box_NONCEBYTES
        ("pk", pointerTo(publicArray(32), 32)),  # public key, size crypto_box_PUBLICKEYBYTES
        ("sk", pointerTo(secretArray(32), 32))  # secret key, size crypto_box_SECRETKEYBYTES
    ])
    state.add_constraints(getArgBVS(state, 'clen') <= max_messagelength)
    addDevURandom(state)
    return (proj, state)

def donna_no_lfence():
    proj = donnaProject()
    state = funcEntryState(proj, "crypto_scalarmult", [
        ("mypublic", pointerTo(publicArray(32), 32)),
        ("secret", pointerTo(secretArray(32), 32)),
        ("basepoint", pointerTo(publicArray(32), 32))
    ])
    addDevURandom(state)
    return (proj, state)

def donna_lfence():
    proj = donnaProject()
    state = funcEntryState(proj, "crypto_scalarmult_lfence", [
        ("mypublic", pointerTo(publicArray(32), 32)),
        ("secret", pointerTo(secretArray(32), 32)),
        ("basepoint", pointerTo(publicArray(32), 32))
    ])
    addDevURandom(state)
    return (proj, state)

def openssl_EVP_PKEY2PKCS8():
    proj = opensslProject()
    state = funcEntryState(proj, "EVP_PKEY2PKCS8", [
        ("pkey", pointerTo(struct([  # pointer to struct evp_pkey_st
            publicValue(), publicValue(),  # type, save_type, and references (total 128 bits I guess?)
            pointerToUnconstrainedPublic(cannotPointSecret=True),  # ameth
            pointerToUnconstrainedPublic(),  # engine
            pointerToUnconstrainedPublic(),  # pmeth_engine
            pointerTo(secretArray(512), 512),  # pkey union. Conservatively estimated to definitely fit within 512 bytes
            publicValue(),  # save_parameters
            pointerToUnconstrainedPublic(),  # attributes
            pointerToUnconstrainedPublic()   # lock
        ]), 128, cannotPointSecret=True))
    ])
    addDevURandom(state)
    return (proj, state)

# Useful approximations to make analysis more tractable

def addDevURandom(state):
    # we don't need the data in /dev/urandom to be symbolic, any concrete data should do
    devurandom = angr.SimFile("devurandom", writable=False, concrete=True, has_end=True,  # if /dev/urandom actually gets to the end of this string and returns EOF, we want to be notified and have things fail rather than have it just invisibly generate symbolic data
        content="fdjkslaiuoewouriejaklhewf,masdnm,fuiorewewrhewjlfawjjkl!$RU(!KshjkLAFjfsdu*(SD(*(*(Asafdlksfjfsisefiklsdanm,fsdhjksfesijlfjesfes,se,esf,jkflesejiolflajiewmn,.waehjkowaejhfofyoivnm,cxhvgudyviuovnxcvncvixocjvsidooiI*DVJSKLFE*#L@N#@$$*Dsjklfjksd8fds9#WU*#(R@$JMksldfjfsd89J*F(F#KLJRJ*(RW")
    state.fs.insert('/dev/urandom', devurandom)
    state.options.discard(angr.options.SHORT_READS)

class HashStub(angr.SimProcedure):
    def run(self, h, m, mlen):
        l.info("stubbing out a call to crypto_hash or crypto_hashblocks")
        for i in range(8):  # 8 uint64_t's to fill 64 bytes
            self.state.mem[h + i*8].uint64_t = self.state.solver.Unconstrained("hash_result", 64, uninitialized=False)
        return 0

def addHashStub(proj):
    proj.hook_symbol("crypto_hash_sha512_tweet", HashStub())

def addHashblocksStub(proj):
    proj.hook_symbol("crypto_hashblocks_sha512_tweet", HashStub())

class RandomBytesStub(angr.SimProcedure):
    """
    Generate unconstrained symbolic secret bytes as output
    """
    def run(self, buf, size_sao):
        l.info("supplying secret randombytes")
        size = self.state.solver.eval_one(size_sao, default=None)
        if size is None:
            raise angr.AngrError("generating a symbolic number of random bytes")
        for i in range(size):
            self.state.mem[buf+i].uint8_t = taintedUnconstrainedBits(self.state, "randombits", 8)

def makeRandomBytesSecret(proj):
    proj.hook_symbol("randombytes", RandomBytesStub())

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
    state.register_plugin('spectre', SpectreExplicitState(args.values()))
    state.spectre.arm(state)
    assert state.spectre.armed()

def makeSpeculative(proj, state, window=250):
    """
    window: size of speculative window (~ROB) in x86 instructions.
    """
    proj.engines.register_plugin('specvex', SimEngineSpecVEX())
    proj.engines.order = ['specvex' if x=='vex' else x for x in proj.engines.order]  # replace 'vex' with 'specvex'
    if proj.engines.has_plugin('vex'): proj.engines.release_plugin('vex')

    #state.options.discard(angr.options.LAZY_SOLVES)  # turns out LAZY_SOLVES is not on by default
    state.register_plugin('spec', SpecState(window))
    state.spec.arm(state)
    assert state.spec.ins_executed == 0

def getSimgr(proj, state, spec=True, window=None):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    """
    if spec:
        if window is not None: makeSpeculative(proj,state,window)
        else: makeSpeculative(proj,state)
    simgr = proj.factory.simgr(state, save_unsat=False)
    if state.has_plugin('oob'):
        simgr.use_technique(OOBViolationFilter())
    if state.has_plugin('spectre'):
        simgr.use_technique(SpectreViolationFilter())
    return simgr

def runSimgr(simgr, **kwargs):
    start = time.process_time()
    simgr.run(step_func=describeActiveStates, **kwargs)
    print("running time: {}".format(time.process_time() - start))
    return simgr

def describeActiveStates(simgr):
    if len(simgr.active) == 0: logstring = "no active states"
    elif len(simgr.active) == 1: logstring = "1 active state, at {}".format(hex(simgr.active[0].addr))
    elif len(simgr.active) <= 8: logstring = "{} active states, at {}".format(len(simgr.active), list(hex(s.addr) for s in simgr.active))
    else: logstring = "{} active states, at {} unique addresses".format(len(simgr.active), len(set(s.addr for s in simgr.active)))
    if 'deadended' in simgr.stashes and len(simgr.deadended) > 0:
        if len(simgr.deadended) == 1:
            logstring += "; 1 state finished"
        else:
            logstring += "; {} states finished".format(len(simgr.deadended))
    if 'spectre_violation' in simgr.stashes and len(simgr.spectre_violation) > 0:
        if len(simgr.spectre_violation) == 1:
            logstring += "; 1 Spectre violation"
        else:
            logstring += "; {} Spectre violations".format(len(simgr.spectre_violation))
    if len(simgr.active) > 0: logstring += ". Max bbs is {}, max #constraints is {}".format(max(len(s.history.bbl_addrs) for s in simgr.active), max(len(s.solver.constraints) for s in simgr.active))
    l.info(logstring)
    return simgr

# 'Driver' functions

def _tweetNaclSimgr(getProjState, funcname, spec=True, window=None, run=True):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    run: if True, runs the simgr before returning it
    """
    l.info("Running TweetNaCl {} {} speculative execution".format(funcname, "with" if spec else "without"))
    proj,state = getProjState()
    armSpectreExplicitChecks(proj,state)
    simgr = getSimgr(proj, state, spec=spec, window=window)
    if run: return runSimgr(simgr)
    else: return simgr

"""
For docs on the arguments to all of the below TweetNaCl functions see docs on _tweetNaclSimgr()
"""

def cryptoSignSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_sign, "crypto_sign", spec=spec, window=window, run=run)

def cryptoSignKeypairSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_sign_keypair, "crypto_sign_keypair", spec=spec, window=window, run=run)

def cryptoSignOpenSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_sign_open, "crypto_sign_open", spec=spec, window=window, run=run)

def cryptoHashSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_hash, "crypto_hash", spec=spec, window=window, run=run)

def cryptoStreamSalsa20Simgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_stream_salsa20, "crypto_stream_salsa20", spec=spec, window=window, run=run)

def cryptoStreamXSalsa20Simgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_stream_xsalsa20, "crypto_stream_xsalsa20", spec=spec, window=window, run=run)

def cryptoOnetimeauthSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_onetimeauth, "crypto_onetimeauth", spec=spec, window=window, run=run)

def cryptoOnetimeauthVerifySimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_onetimeauth_verify, "crypto_onetimeauth_verify", spec=spec, window=window, run=run)

def cryptoSecretBoxSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_secretbox, "crypto_secretbox", spec=spec, window=window, run=run)

def cryptoSecretBoxOpenSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_secretbox_open, "crypto_secretbox_open", spec=spec, window=window, run=run)

def cryptoBoxSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_box, "crypto_box", spec=spec, window=window, run=run)

def cryptoBoxOpenSimgr(spec=True, window=None, run=True):
    return _tweetNaclSimgr(tweetnacl_crypto_box_open, "crypto_box_open", spec=spec, window=window, run=run)

def kocherSimgr(s, spec=True, window=None, run=True):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    run: if True, runs the simgr before returning it
    """
    l.info("Running Kocher test case {} {} speculative execution".format(s, "with" if spec else "without"))
    proj,state = kocher(s)
    armSpectreOOBChecks(proj,state)
    simgr = getSimgr(proj, state, spec=spec, window=window)
    if run: return runSimgr(simgr)
    else: return simgr

def kocher11Simgr(s, spec=True, window=None, run=True):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    run: if True, runs the simgr before returning it
    """
    l.info("Running Kocher test case 11{} {} speculative execution".format(s, "with" if spec else "without"))
    proj,state = kocher11(s)
    armSpectreOOBChecks(proj,state)
    simgr = getSimgr(proj, state, spec=spec, window=window)
    if run: return runSimgr(simgr)
    else: return simgr

def donnaSimgr(lfence=False, spec=True, window=None, run=True):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    run: if True, runs the simgr before returning it
    """
    l.info("Running Donna {} lfence and {} speculative execution".format("with" if lfence else "without", "with" if spec else "without"))
    proj,state = donna_lfence() if lfence else donna_no_lfence()
    armSpectreExplicitChecks(proj,state)
    simgr = getSimgr(proj, state, spec=spec, window=window)
    if run: return runSimgr(simgr)
    else: return simgr

def openssl_EVP_PKEY2PKCS8_simgr(spec=True, window=None, run=True):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    run: if True, runs the simgr before returning it
    """
    l.info("Running OpenSSL EVP_PKEY2PKCS8 {} speculative execution".format("with" if spec else "without"))
    proj,state = openssl_EVP_PKEY2PKCS8()
    armSpectreExplicitChecks(proj,state)
    simgr = getSimgr(proj, state, spec=spec, window=window)
    if run: return runSimgr(simgr)
    else: return simgr

def runallTweetNacl(spec=True, window=None):
    return { "crypto_sign":cryptoSignSimgr(spec=spec, window=window),
             "crypto_sign_keypair":cryptoSignKeypairSimgr(spec=spec, window=window),
             "crypto_stream_salsa20":cryptoStreamSalsa20Simgr(spec=spec, window=window),
             "crypto_stream_xsalsa20":cryptoStreamXSalsa20Simgr(spec=spec, window=window),
             "crypto_onetimeauth":cryptoOnetimeauthSimgr(spec=spec, window=window),
             "crypto_onetimeauth_verify":cryptoOnetimeauthVerifySimgr(spec=spec, window=window),
             "crypto_secretbox":cryptoSecretBoxSimgr(spec=spec, window=window),
             "crypto_secretbox_open":cryptoSecretBoxOpenSimgr(spec=spec, window=window),
             "crypto_box":cryptoBoxSimgr(spec=spec, window=window),
             "crypto_box_open":cryptoBoxOpenSimgr(spec=spec, window=window)
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
        {s:kocherSimgr(s, spec=spec, window=window) for s in ['01','02','03','05','07','04','06','08','09','10','12','13','14','15']},
        {('11'+s):kocher11Simgr(s, spec=spec, window=window) for s in ['gcc','ker','sub']})

def alltests(kocher=True, tweetnacl=True):
    """
    kocher: whether to run Kocher tests
    tweetnacl: whether to run TweetNaCl tests
    """
    if not kocher and not tweetnacl:
        raise ValueError("no tests specified")
    logging.getLogger('specvex').setLevel(logging.WARNING)
    logging.getLogger('spectre').setLevel(logging.WARNING)
    logging.getLogger('oob').setLevel(logging.WARNING)
    if kocher:
        kocher_notspec = runallKocher(spec=False)
        kocher_spec = runallKocher(spec=True)
    if tweetnacl:
        tweetnacl_notspec = runallTweetNacl(spec=False)
        tweetnacl_spec = runallTweetNacl(spec=True)
    def violationDetected(simgr):
        return 'spectre_violation' in simgr.stashes and len(simgr.spectre_violation) > 0
    def kocher_testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(kocher_notspec[s])
            else "FAIL: no violation detected" if not violationDetected(kocher_spec[s])
            else "PASS")
    def tweetnacl_testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(tweetnacl_notspec[s])
            else "violation detected" if violationDetected(tweetnacl_spec[s])
            else "no violation detected")
    if kocher:
        kocher_results = {k:kocher_testResult(k) for k in kocher_spec.keys()}
    if tweetnacl:
        tweetnacl_results = {k:tweetnacl_testResult(k) for k in tweetnacl_spec.keys()}
    if kocher and not tweetnacl:
        print("Kocher tests:")
        return kocher_results
    elif tweetnacl and not kocher:
        print("TweetNaCl tests:")
        return tweetnacl_results
    elif tweetnacl and kocher:
        return {"Kocher tests":kocher_results,
                "TweetNaCl tests":tweetnacl_results}

def unionDicts(dicta, dictb):
    return {**dicta, **dictb}  # requires Python 3.5+

if __name__ == '__main__':
    from pprint import pprint
    pprint(alltests(tweetnacl=False))
