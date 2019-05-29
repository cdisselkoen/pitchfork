from specvex import makeSpeculative
from oob import OOBState, OOBViolationFilter
from spectre import SpectreOOBState, SpectreExplicitState, SpectreViolationFilter
from irop_hook import IROpHook
from interactiveutils import *  #pylint:disable=unused-wildcard-import
from stubs import *  #pylint:disable=unused-wildcard-import
from abstractdata import publicValue, secretValue, pointerTo, pointerToUnconstrainedPublic, publicArray, secretArray, array, struct

import angr
import claripy
import logging
l = logging.getLogger(name=__name__)

try:
    import monkeyhex
except:
    pass
import time

#logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.DEBUG)
#logging.getLogger('angr.engines').setLevel(logging.INFO)
#logging.getLogger('specvex').setLevel(logging.DEBUG)
logging.getLogger('spectre').setLevel(logging.INFO)
logging.getLogger('oob').setLevel(logging.DEBUG)
#logging.getLogger('irop_hook').setLevel(logging.DEBUG)
logging.getLogger('stubs').setLevel(logging.INFO)
logging.getLogger(__name__).setLevel(logging.INFO)

def getAddressOfSymbol(proj, symbolname):
    symb = proj.loader.find_symbol(symbolname)
    if symb is None:
        raise ValueError("symbol name {} not found".format(symbolname))
    return symb.rebased_addr

def funcEntryState(proj, funcname, args):
    """
    Get a state ready to enter the given function, with each argument
        as a fully unconstrained 64-bit value.
    funcname: name of the function to enter
    args: a list of n values, one for each function argument, each of which
        is a pair (name, val) where:
        name: either None, in which case you get a default name 'arg1', 'arg2', etc
            or a custom name to use for the argument BVS
        val: an AbstractValue denoting the structure of the argument, including its bitlength
            See notes in abstractdata.py
    """
    funcaddr = getAddressOfSymbol(proj, funcname)
    argnames = list("arg{}".format(i) if name is None else name for (i, (name, _)) in enumerate(args))
    argBVSs = list(claripy.BVS(name, val.bits) for (name, (_, val)) in zip(argnames, args))
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
    if s == '10':
        state = funcEntryState(proj, funcname, [(None, publicValue()), (None, publicValue(bits=8))])
    elif s == '12':
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

def newSpectreV1TestcasesProject():
    return angr.Project('new-testcases/spectrev1')

def forwardingTestcasesProject():
    return angr.Project('new-testcases/forwarding')

def tweetnaclProject():
    proj = angr.Project('tweetnacl/testbinaryO3')
    makeRandomBytesSecret(proj)
    return proj

def donnaProject():
    return angr.Project('x25519bench/test')

def opensslProject():
    return angr.Project('openssl/openssl')

def addSecretObject(proj, state, symbol, length):
    """
    In the given state, mark the given symbol with the given length (in bytes) as secret.
    """
    secretaddr = getAddressOfSymbol(proj, symbol)
    prevSecrets = state.globals.get('otherSecrets', [])
    state.globals['otherSecrets'] = [(secretaddr, secretaddr+length)] + prevSecrets

def forwarding_example_1():
    proj = forwardingTestcasesProject()
    state = funcEntryState(proj, "example_1", [
        ("idx", publicValue(bits=64)),
        ("val", publicValue(bits=8)),
        ("idx2", publicValue(bits=64))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def forwarding_example_2():
    proj = forwardingTestcasesProject()
    state = funcEntryState(proj, "example_2", [
        ("idx", publicValue(bits=64))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def forwarding_example_3():
    proj = forwardingTestcasesProject()
    state = funcEntryState(proj, "example_3", [
        ("idx", publicValue(bits=64)),
        ("mask", publicValue(bits=8))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def forwarding_example_4():
    proj = forwardingTestcasesProject()
    state = funcEntryState(proj, "example_4", [])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def forwarding_example_5():
    proj = forwardingTestcasesProject()
    state = funcEntryState(proj, "example_5", [
        ("idx", publicValue(bits=64)),
        ("val", publicValue(bits=8)),
        ("idx2", publicValue(bits=64))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def _typicalSpectrev1Case(casename):
    proj = newSpectreV1TestcasesProject()
    state = funcEntryState(proj, casename, [ ("idx", publicValue(bits=64)) ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def spectrev1_case_1():
    return _typicalSpectrev1Case("case_1")

def spectrev1_case_2():
    return _typicalSpectrev1Case("case_2")

def spectrev1_case_3():
    return _typicalSpectrev1Case("case_3")

def spectrev1_case_4():
    return _typicalSpectrev1Case("case_4")

def spectrev1_case_5():
    return _typicalSpectrev1Case("case_5")

def spectrev1_case_6():
    return _typicalSpectrev1Case("case_6")

def spectrev1_case_7():
    return _typicalSpectrev1Case("case_7")

def spectrev1_case_8():
    return _typicalSpectrev1Case("case_8")

def spectrev1_case_9():
    return _typicalSpectrev1Case("case_9")

def spectrev1_case_10():
    proj = newSpectreV1TestcasesProject()
    state = funcEntryState(proj, "case_10", [
        ("idx", publicValue(bits=64)),
        ("val", publicValue(bits=8))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def spectrev1_case_11gcc():
    return _typicalSpectrev1Case("case_11gcc")

def spectrev1_case_11ker():
    return _typicalSpectrev1Case("case_11ker")

def spectrev1_case_11sub():
    return _typicalSpectrev1Case("case_11sub")

def spectrev1_case_12():
    proj = newSpectreV1TestcasesProject()
    state = funcEntryState(proj, "case_12", [
        ("idx", publicValue(bits=64)),
        ("val", publicValue(bits=8))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def spectrev1_case_13():
    return _typicalSpectrev1Case("case_13")

def spectrev1_case_14():
    return _typicalSpectrev1Case("case_14")

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

def abstractEVP_PKEY(engineNull=True):
    """
    Abstract representation of an EVP_PKEY aka struct evp_pkey_st
    engineNull: if True, then the 'engine' field will be forced to NULL rather than unconstrained
    """
    return struct([
        publicValue(bits=32),  # type
        publicValue(bits=32),  # save_type
        publicValue(bits=64), # references (experimentally seems to be 64 bits?)
        pointerToUnconstrainedPublic(maxPointeeSize=36*8, cannotPointSecret=True),  # ameth
        publicValue(0) if engineNull else pointerToUnconstrainedPublic(cannotPointSecret=True),  # engine
        pointerToUnconstrainedPublic(cannotPointSecret=True),  # pmeth_engine
        pointerTo(secretArray(512), 512),  # pkey union. Conservatively estimated to definitely fit within 512 bytes
        publicValue(),  # save_parameters
        pointerToUnconstrainedPublic(cannotPointSecret=True),  # attributes
        pointerToUnconstrainedPublic(cannotPointSecret=True)   # lock
    ])

def openssl_EVP_PKEY2PKCS8():
    proj = opensslProject()
    state = funcEntryState(proj, "EVP_PKEY2PKCS8", [
        ("pkey", pointerTo(abstractEVP_PKEY(), 128, cannotPointSecret=True))
    ])
    addDevURandom(state)
    addEVPStubs(proj)
    return (proj, state)

def openssl_ASN1_item_sign():
    proj = opensslProject()
    state = funcEntryState(proj, "ASN1_item_sign", [
        ("it", pointerToUnconstrainedPublic()),
        ("algor1", pointerToUnconstrainedPublic()),
        ("algor2", pointerToUnconstrainedPublic()),
        ("signature", pointerToUnconstrainedPublic()),
        ("asn", pointerToUnconstrainedPublic()),
        ("pkey", pointerTo(abstractEVP_PKEY(), 128, cannotPointSecret=True)),
        ("type", pointerToUnconstrainedPublic())
    ])
    addDevURandom(state)
    addEVPStubs(proj)
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
    otherSecrets = state.globals['otherSecrets'] if 'otherSecrets' in state.globals else []
    state.register_plugin('spectre', SpectreExplicitState(vars=args.values(), secretIntervals=otherSecrets))
    state.spectre.arm(state)
    assert state.spectre.armed()

def getSimgr(proj, state, spec=True, window=None, misforwarding=False):
    """
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    misforwarding: whether to enable misforwarding features, i.e., speculatively
        missing a forward from an inflight store. No effect if spec=False.
    """
    if spec:
        if window is not None: makeSpeculative(proj,state,window,misforwarding=misforwarding)
        else: makeSpeculative(proj,state,misforwarding=misforwarding)
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

def _spectreSimgr(getProjState, getProjStateArgs, funcname, checks, spec=True, window=None, misforwarding=False, run=True):
    """
    getProjState: a function which, when called with getProjStateArgs, produces a pair (proj, state)
    getProjStateArgs: list of arguments to pass to the getProjState function
    funcname: name of the function being executed, for logging purposes only
    checks: either 'OOB' for SpectreOOBChecks or 'explicit' for SpectreExplicitChecks
    spec: whether to enable speculative execution
    window: size of speculative window (~ROB) in x86 instructions. None (the default) to use default value
    misforwarding: whether to enable misforwarding features, i.e., speculatively
        missing a forward from an inflight store. No effect if spec=False.
    run: if True, runs the simgr before returning it
    """
    l.info("Running {} {} speculative execution".format(funcname, "with" if spec else "without"))
    proj,state = getProjState(*getProjStateArgs)
    if checks == 'OOB': armSpectreOOBChecks(proj,state)
    elif checks == 'explicit': armSpectreExplicitChecks(proj,state)
    else: raise ValueError("Expected `checks` to be either 'OOB' or 'explicit', got {}".format(checks))
    simgr = getSimgr(proj, state, spec=spec, window=window, misforwarding=misforwarding)
    if run: return runSimgr(simgr)
    else: return simgr

"""
All of the below simgr-related functions can take any of the keyword arguments that
    _spectreSimgr() takes, i.e., `spec`, `window`, `misforwarding`, and `run`.
See docs on _spectreSimgr().
"""

def spectrev1case1Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_1, [], "Spectre v1 case 1", "explicit", **kwargs)

def spectrev1case2Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_2, [], "Spectre v1 case 2", "explicit", **kwargs)

def spectrev1case3Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_3, [], "Spectre v1 case 3", "explicit", **kwargs)

def spectrev1case4Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_4, [], "Spectre v1 case 4", "explicit", **kwargs)

def spectrev1case5Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_5, [], "Spectre v1 case 5", "explicit", **kwargs)

def spectrev1case6Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_6, [], "Spectre v1 case 6", "explicit", **kwargs)

def spectrev1case7Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_7, [], "Spectre v1 case 7", "explicit", **kwargs)

def spectrev1case8Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_8, [], "Spectre v1 case 8", "explicit", **kwargs)

def spectrev1case9Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_9, [], "Spectre v1 case 9", "explicit", **kwargs)

def spectrev1case10Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_10, [], "Spectre v1 case 10", "explicit", **kwargs)

def spectrev1case11gccSimgr(**kwargs):
    return _spectreSimgr(spectrev1_case_11gcc, [], "Spectre v1 case 11gcc", "explicit", **kwargs)

def spectrev1case11kerSimgr(**kwargs):
    return _spectreSimgr(spectrev1_case_11ker, [], "Spectre v1 case 11ker", "explicit", **kwargs)

def spectrev1case11subSimgr(**kwargs):
    return _spectreSimgr(spectrev1_case_11sub, [], "Spectre v1 case 11sub", "explicit", **kwargs)

def spectrev1case12Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_12, [], "Spectre v1 case 12", "explicit", **kwargs)

def spectrev1case13Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_13, [], "Spectre v1 case 13", "explicit", **kwargs)

def spectrev1case14Simgr(**kwargs):
    return _spectreSimgr(spectrev1_case_14, [], "Spectre v1 case 14", "explicit", **kwargs)

def forwarding1Simgr(**kwargs):
    return _spectreSimgr(forwarding_example_1, [], "forwarding example 1", "explicit", **kwargs)

def forwarding2Simgr(**kwargs):
    return _spectreSimgr(forwarding_example_2, [], "forwarding example 2", "explicit", **kwargs)

def forwarding3Simgr(**kwargs):
    return _spectreSimgr(forwarding_example_3, [], "forwarding example 3", "explicit", **kwargs)

def forwarding4Simgr(**kwargs):
    window = kwargs.pop('window', 20)  # default to window size 20, which should be sufficient for this example. Respects the manual 'window' setting if the caller passed a 'window' argument though
    return _spectreSimgr(forwarding_example_4, [], "forwarding example 4", "explicit", window=window, **kwargs)

def forwarding5Simgr(**kwargs):
    return _spectreSimgr(forwarding_example_5, [], "forwarding example 5", "explicit", **kwargs)

def cryptoSignSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_sign, [], "TweetNaCl crypto_sign", "explicit", **kwargs)

def cryptoSignKeypairSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_sign_keypair, [], "TweetNaCl crypto_sign_keypair", "explicit", **kwargs)

def cryptoSignOpenSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_sign_open, [], "TweetNaCl crypto_sign_open", "explicit", **kwargs)

def cryptoHashSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_hash, [], "TweetNaCl crypto_hash", "explicit", **kwargs)

def cryptoStreamSalsa20Simgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_stream_salsa20, [], "TweetNaCl crypto_stream_salsa20", "explicit", **kwargs)

def cryptoStreamXSalsa20Simgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_stream_xsalsa20, [], "TweetNaCl crypto_stream_xsalsa20", "explicit", **kwargs)

def cryptoOnetimeauthSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_onetimeauth, [], "TweetNaCl crypto_onetimeauth", "explicit", **kwargs)

def cryptoOnetimeauthVerifySimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_onetimeauth_verify, [], "TweetNaCl crypto_onetimeauth_verify", "explicit", **kwargs)

def cryptoSecretBoxSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_secretbox, [], "TweetNaCl crypto_secretbox", "explicit", **kwargs)

def cryptoSecretBoxOpenSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_secretbox_open, [], "TweetNaCl crypto_secretbox_open", "explicit", **kwargs)

def cryptoBoxSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_box, [], "TweetNaCl crypto_box", "explicit", **kwargs)

def cryptoBoxOpenSimgr(**kwargs):
    return _spectreSimgr(tweetnacl_crypto_box_open, [], "TweetNaCl crypto_box_open", "explicit", **kwargs)

def kocherSimgr(s, **kwargs):
    return _spectreSimgr(kocher, [s], "Kocher test case " + s, "OOB", **kwargs)

def kocher11Simgr(s, **kwargs):
    return _spectreSimgr(kocher11, [s], "Kocher test case 11" + s, "OOB", **kwargs)

def donnaSimgr(lfence=False, **kwargs):
    return _spectreSimgr(donna_lfence if lfence else donna_no_lfence, [], "Donna {} lfence".format("with" if lfence else "without"), "explicit", **kwargs)

def openssl_EVP_PKEY2PKCS8_simgr(**kwargs):
    return _spectreSimgr(openssl_EVP_PKEY2PKCS8, [], "OpenSSL EVP_PKEY2PKCS8", "explicit", **kwargs)

def openssl_ASN1_item_sign_simgr(**kwargs):
    return _spectreSimgr(openssl_ASN1_item_sign, [], "OpenSSL ASN1_item_sign", "explicit", **kwargs)

def runallTweetNacl(**kwargs):
    return { "crypto_sign":cryptoSignSimgr(**kwargs),
             "crypto_sign_keypair":cryptoSignKeypairSimgr(**kwargs),
             "crypto_stream_salsa20":cryptoStreamSalsa20Simgr(**kwargs),
             "crypto_stream_xsalsa20":cryptoStreamXSalsa20Simgr(**kwargs),
             "crypto_onetimeauth":cryptoOnetimeauthSimgr(**kwargs),
             "crypto_onetimeauth_verify":cryptoOnetimeauthVerifySimgr(**kwargs),
             "crypto_secretbox":cryptoSecretBoxSimgr(**kwargs),
             "crypto_secretbox_open":cryptoSecretBoxOpenSimgr(**kwargs),
             "crypto_box":cryptoBoxSimgr(**kwargs),
             "crypto_box_open":cryptoBoxOpenSimgr(**kwargs),
           }

def runallKocher(**kwargs):
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
        {s:kocherSimgr(s, **kwargs) for s in ['01','02','03','05','07','04','06','08','09','10','12','13','14','15']},
        {('11'+s):kocher11Simgr(s, **kwargs) for s in ['gcc','ker','sub']})

def runallSpectrev1(**kwargs):
    return { "01" : spectrev1case1Simgr(**kwargs),
             "02" : spectrev1case2Simgr(**kwargs),
             "03" : spectrev1case3Simgr(**kwargs),
             "04" : spectrev1case4Simgr(**kwargs),
             "05" : spectrev1case5Simgr(**kwargs),
             "06" : spectrev1case6Simgr(**kwargs),
             "07" : spectrev1case7Simgr(**kwargs),
             "08" : spectrev1case8Simgr(**kwargs),
             "09" : spectrev1case9Simgr(**kwargs),
             "10" : spectrev1case10Simgr(**kwargs),
             "11gcc" : spectrev1case11gccSimgr(**kwargs),
             "11ker" : spectrev1case11kerSimgr(**kwargs),
             "11sub" : spectrev1case11subSimgr(**kwargs),
             "12" : spectrev1case12Simgr(**kwargs),
             "13" : spectrev1case13Simgr(**kwargs),
             "14" : spectrev1case14Simgr(**kwargs)
           }

def runallForwarding(**kwargs):
    return { "1" : forwarding1Simgr(**kwargs),
             "2" : forwarding2Simgr(**kwargs),
             "3" : forwarding3Simgr(**kwargs),
             "4" : forwarding4Simgr(**kwargs),
             "5" : forwarding5Simgr(**kwargs)
           }

def alltests(kocher=True, spectrev1=True, forwarding=True, tweetnacl=True):
    """
    kocher: whether to run Kocher tests
    spectrev1: whether to run the new spectrev1 tests
    forwarding: whether to run forwarding tests
    tweetnacl: whether to run TweetNaCl tests
    """
    from pprint import pprint
    if not kocher and not spectrev1 and not forwarding and not tweetnacl:
        raise ValueError("no tests specified")
    logging.getLogger('specvex').setLevel(logging.WARNING)
    logging.getLogger('spectre').setLevel(logging.WARNING)
    logging.getLogger('oob').setLevel(logging.WARNING)
    if kocher:
        kocher_notspec = runallKocher(spec=False)
        kocher_spec = runallKocher(spec=True)
    if spectrev1:
        spectrev1_notspec = runallSpectrev1(spec=False)
        spectrev1_spec = runallSpectrev1(spec=True)
    if forwarding:
        forwarding_notspec = runallForwarding(spec=False)
        forwarding_spec = runallForwarding(spec=True, misforwarding=False)
        forwarding_forwarding = runallForwarding(spec=True, misforwarding=True)
    if tweetnacl:
        tweetnacl_notspec = runallTweetNacl(spec=False)
        tweetnacl_spec = runallTweetNacl(spec=True)
    def violationDetected(simgr):
        return 'spectre_violation' in simgr.stashes and len(simgr.spectre_violation) > 0
    def kocher_testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(kocher_notspec[s])
            else "FAIL: no violation detected" if not violationDetected(kocher_spec[s])
            else "PASS")
    def spectrev1_testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(spectrev1_notspec[s])
            else "FAIL: no violation detected" if not violationDetected(spectrev1_spec[s])
            else "PASS")
    def forwarding_testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(forwarding_notspec[s])
            else "FAIL: detected a violation without misforwarding" if violationDetected(forwarding_spec[s])
            else "FAIL: no violation detected" if not violationDetected(forwarding_forwarding[s])
            else "PASS")
    def tweetnacl_testResult(s):
        return ("FAIL: detected a violation without speculative execution" if violationDetected(tweetnacl_notspec[s])
            else "violation detected" if violationDetected(tweetnacl_spec[s])
            else "no violation detected")
    kocher_results = {k:kocher_testResult(k) for k in kocher_spec.keys()} if kocher else None
    spectrev1_results = {k:spectrev1_testResult(k) for k in spectrev1_spec.keys()} if spectrev1 else None
    forwarding_results = {k:forwarding_testResult(k) for k in forwarding_spec.keys()} if forwarding else None
    tweetnacl_results = {k:tweetnacl_testResult(k) for k in tweetnacl_spec.keys()} if tweetnacl else None
    if kocher and not spectrev1 and not forwarding and not tweetnacl:
        print("Kocher tests:")
        pprint(kocher_results)
    elif spectrev1 and not kocher and not forwarding and not tweetnacl:
        print("Spectrev1 tests:")
        pprint(spectrev1_results)
    elif forwarding and not kocher and not spectrev1 and not tweetnacl:
        print("Forwarding tests:")
        pprint(forwarding_results)
    elif tweetnacl and not kocher and not spectrev1 and not forwarding:
        print("TweetNaCl tests:")
        pprint(tweetnacl_results)
    else:
        pprint({"Kocher tests":kocher_results,
                "Spectrev1 tests":spectrev1_results,
                "Forwarding tests":forwarding_results,
                "TweetNaCl tests":tweetnacl_results})

def unionDicts(dicta, dictb):
    return {**dicta, **dictb}  # requires Python 3.5+

if __name__ == '__main__':
    alltests(tweetnacl=False)
