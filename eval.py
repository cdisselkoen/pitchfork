#!/usr/bin/env python3

import argparse

import pitchfork
from pitchfork import angr, funcEntryState, _spectreSimgr
from abstractdata import publicValue, secretValue, pointerTo, pointerToUnconstrainedPublic, publicArray, secretArray, array, struct

import logging
l = logging.getLogger(__name__)
l.setLevel(logging.INFO)

def c_donna(args, generating_fname=False):
    parser = argparse.ArgumentParser('c_donna')
    args = parser.parse_args(args)
    if generating_fname:
        return ''
    proj = angr.Project('fact-eval/c_donna')
    state = funcEntryState(proj, "curve25519_donna", [
        ("mypublic", pointerTo(secretArray(32), 32)),
        ("_secret", pointerTo(secretArray(32), 32)),
        ("basepoint", pointerTo(publicArray(32), 32)),
    ])
    return proj, state, "C donna", None

def fact_donna(args, generating_fname=False):
    parser = argparse.ArgumentParser('fact_donna')
    args = parser.parse_args(args)
    if generating_fname:
        return ''
    # this is O2 optimized fact
    proj = angr.Project('fact-eval/fact_donna')
    state = funcEntryState(proj, "curve25519_donna", [
        ("mypublic", pointerTo(secretArray(32), 32)),
        ("_secret", pointerTo(secretArray(32), 32)),
        ("basepoint", pointerTo(publicArray(32), 32)),
    ])
    return proj, state, "FaCT donna", None

def c_ssl3(args, generating_fname=False):
    parser = argparse.ArgumentParser('c_ssl3')
    args = parser.parse_args(args)
    if generating_fname:
        return ''
    proj = angr.Project('fact-eval/c_s3_cbc.O3')
    thing = publicValue(value=4)
    ctx_struct = [
        pointerTo(thing),
        publicArray(256),
    ]
    ctx = struct(ctx_struct)
    state = funcEntryState(proj, "ssl3_cbc_digest_record", [
        ("ctx", pointerTo(ctx)),
        ("md_out", pointerTo(secretArray(64), 64)),
        ("md_out_size", publicValue(64)),
        ("header", pointerTo(secretArray(16), 16)),
        ("data", pointerTo(secretArray(256), 256)), # XXX should be unconstrained
        ("data_plus_mac_size", secretValue()),
        ("data_plus_mac_plus_padding_size", publicValue(256)),
        ("mac_secret", pointerTo(secretArray(32), 32)),
        ("mac_secret_length", publicValue(32)),
        ("is_sslv3", publicValue(0, bits=8)),
    ])
    # XXX add constraints
    return proj, state, "C ssl3", None, '0011001000100010101000'

def fact_ssl3(args, generating_fname=False):
    parser = argparse.ArgumentParser('fact_ssl3')
    args = parser.parse_args(args)
    if generating_fname:
        return ''
    proj = angr.Project('fact-eval/fact_s3_cbc.O3')
    state = funcEntryState(proj, "__ssl3_cbc_digest_record", [
        ("md_state", pointerTo(secretArray(216), 216)),
        ("mac_out", pointerTo(secretArray(64), 64)),
        ("basepoint", pointerTo(publicArray(32), 32)),
        ("header", pointerTo(secretArray(16), 16)),
        ("__header_len", publicValue(16)),
        ("data", pointerTo(secretArray(256), 256)), # XXX should be unconstrained
        ("__data_len", publicValue(256)),
        ("data_plus_mac_size", secretValue()),
    ])
    # XXX add constraints
    return proj, state, "FaCT ssl3", None

class AesStub(angr.SimProcedure):
    def run(self, in_, out, len_, key, iv, enc):
        l.info("stubbing out a call to aesni_cbc_encrypt")
        return

def c_mee(args, generating_fname=False):
    if generating_fname:
        return ''
    binary = 'fact-eval/c_mee.O3'
    declassified_load = 0x516c5f
    proj = angr.Project(binary)
    proj.hook_symbol("aesni_cbc_encrypt", AesStub())
    aes_key_ks = [
        [secretValue(bits=32) for _ in range(60)], # 0..ef
        publicValue(bits=32), # f0..f3
    ]
    sha_ctx_head = [
        [secretValue(bits=32) for _ in range(5)], # f4..107
        publicValue(bits=32), # 108..10b
        publicValue(bits=32), # 10c..10f
        secretArray(64), # 110..14f
        publicValue(bits=32), # 150..153
    ]
    sha_ctx_tail = [
        [secretValue(bits=32) for _ in range(5)], # 154..167
        publicValue(bits=32), # 168..16b
        publicValue(bits=32), # 16c..16f
        secretArray(64), # 170..1af
        publicValue(bits=32), # 1b0..1b3
    ]
    sha_ctx_md = [
        [secretValue(bits=32) for _ in range(5)], # 1b4
        publicValue(bits=32),
        publicValue(bits=32),
        secretArray(64),
        publicValue(bits=32),
    ]
    evp_aes_hmac_sha1 = [
        aes_key_ks,
        sha_ctx_head,
        sha_ctx_tail,
        sha_ctx_md,
        publicValue(bits=32), # [pad] 214..217
        publicValue(13, bits=64), # 218..21f
        [publicValue(bits=8) for _ in range(16)],
        #[publicValue(bits=8) for _ in range(9)] + [publicValue(0x0302, bits=16), publicValue(bits=16)],
        secretArray(16),
    ]
    evp_cipher_ctx_st = [
        pointerToUnconstrainedPublic(), # cipher
        pointerToUnconstrainedPublic(), # engine
        publicValue(0, bits=32), # encrypt
        publicValue(bits=32), # buf_len
        publicArray(16), # oiv
        publicArray(16), # iv
        publicArray(32), # buf
        publicValue(bits=32), # num
        publicValue(bits=32), # [padding]
        pointerToUnconstrainedPublic(), # app_data
        publicValue(bits=32), # key_len
        publicValue(bits=32), # [padding]
        publicValue(bits=64), # flags
        pointerTo(struct(evp_aes_hmac_sha1)), # cipher_data
        publicValue(bits=32), # final_used
        publicValue(bits=32), # block_mask
        publicArray(32), # final
    ]
    ctx = struct(evp_cipher_ctx_st)
    state = funcEntryState(proj, "aesni_cbc_hmac_sha1_cipher", [
        ("ctx", pointerTo(ctx)),
        ("out", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
        ("in", pointerTo(publicArray(1024), 1024)), # XXX should be unconstrained
        ("len", publicValue(1024, bits=64)),
    ])
    return proj, state, "mee", [declassified_load], '00110010011001111011'

def fact_mee(args, generating_fname=False):
    parser = argparse.ArgumentParser('fact_mee')
    parser.add_argument('--unopt', action='store_true')
    args = parser.parse_args(args)
    if generating_fname:
        fname = ''
        argsd= dict(vars(args))
        for arg in sorted(argsd):
            val = argsd[arg]
            sarg = ''
            if arg == 'unopt':
                if val:
                    sarg = 'unopt'
                else:
                    sarg = 'O3'
            elif arg == 'mod':
                if val:
                    sarg = 'mod'
            else:
                sarg = arg_to_fname(arg, val)
            if sarg:
                fname += '.' + sarg
        return fname
    print(args, flush=True)
    binary = 'fact-eval/fact_mee'
    declassified_load = 0x401cf3
    if not args.unopt:
        binary += '.O3'
        declassified_load = 0x401854
    proj = angr.Project(binary)
    aes_key_ks = [
        [secretValue(bits=32) for _ in range(60)], # 0..ef
        publicValue(bits=32), # f0..f3
    ]
    sha_ctx_head = [
        [secretValue(bits=32) for _ in range(5)], # f4..107
        publicValue(bits=32), # 108..10b
        publicValue(bits=32), # 10c..10f
        secretArray(64), # 110..14f
        publicValue(bits=32), # 150..153
    ]
    sha_ctx_tail = [
        [secretValue(bits=32) for _ in range(5)], # 154..167
        publicValue(bits=32), # 168..16b
        publicValue(bits=32), # 16c..16f
        secretArray(64), # 170..1af
        publicValue(bits=32), # 1b0..1b3
    ]
    sha_ctx_md = [
        [secretValue(bits=32) for _ in range(5)], # 1b4..1c7
        publicValue(bits=32), # 1c8..1cb
        publicValue(bits=32), # 1cc..1cf
        secretArray(64), # 1d0..20f
        publicValue(bits=32), # 210..213
    ]
    evp_aes_hmac_sha1 = [
        aes_key_ks,
        sha_ctx_head,
        sha_ctx_tail,
        sha_ctx_md,
        publicValue(bits=64), # 218
        secretArray(16),
    ]
    evp_aes_hmac_sha1 = struct(evp_aes_hmac_sha1)
    state = funcEntryState(proj, "_aesni_cbc_hmac_sha1_cipher", [
        ("iv", pointerTo(publicArray(16), 16)),
        ("key", pointerTo(evp_aes_hmac_sha1)),
        ("out", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
        ("out_len", publicValue(1024, bits=64)),
        ("in", pointerTo(publicArray(1024), 1024)), # XXX should be unconstrained
        ("in_len", publicValue(1024, bits=64)),
        ("tls_ver", publicValue(0x0302, bits=16)),
    ])
    return proj, state, "mee", [declassified_load]

def c_secretbox(args, generating_fname=False):
    parser = argparse.ArgumentParser('c_secretbox')
    parser.add_argument('--asm', action='store_true')
    parser.add_argument('--open', action='store_true')
    args = parser.parse_args(args)
    if generating_fname:
        fname = ''
        argsd= dict(vars(args))
        if argsd['open']:
            fname += '_open'
        del argsd['open']
        argsd['opt'] = 'O2'
        for arg in sorted(argsd):
            val = argsd[arg]
            sarg = ''
            if arg == 'asm':
                if val:
                    sarg = 'asm'
                else:
                    sarg = 'cref'
            else:
                sarg = arg_to_fname(arg, val)
            if sarg:
                fname += '.' + sarg
        return fname
    print(args, flush=True)
    binary = 'fact-eval/c_secretbox'
    if args.asm:
        binary += '.asm'
    else:
        binary += '.cref'
    binary += '.O2'
    proj = angr.Project(binary)
    fname = 'crypto_secretbox'

    path = ''
    declassified_verify_branch = []
    if args.open:
        fname += '_open'
        params = [
            ("m", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
            ("c", pointerTo(publicArray(1024), 1024)), # XXX should be unconstrained
            ("clen", publicValue(1024, bits=64)),
        ]
        declassified_verify_branch = 0x401d80
        path = '1011001000100010101000'
    else:
        params = [
            ("c", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
            ("m", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
            ("mlen", publicValue(1024, bits=64)),
        ]
        if args.asm:
            path = '0100000000011001011001000100010101000'
        else:
            path = '01000000000110110010011001111011'
    params += [
        ("n", pointerTo(publicArray(24), 24)),
        ("k", pointerTo(secretArray(32), 32)),
    ]
    state = funcEntryState(proj, fname, params)
    return proj, state, fname, [declassified_verify_branch], path

def fact_secretbox(args, generating_fname=False):
    parser = argparse.ArgumentParser('fact_secretbox')
    parser.add_argument('--asm', action='store_true')
    parser.add_argument('--unopt', action='store_true')
    parser.add_argument('--open', action='store_true')
    args = parser.parse_args(args)
    if generating_fname:
        fname = ''
        argsd= dict(vars(args))
        if argsd['open']:
            fname += '_open'
        del argsd['open']
        for arg in sorted(argsd):
            val = argsd[arg]
            sarg = ''
            if arg == 'unopt':
                if val:
                    sarg = 'unopt'
                else:
                    sarg = 'O2'
            elif arg == 'asm':
                if val:
                    sarg = 'asm'
                else:
                    sarg = 'cref'
            else:
                sarg = arg_to_fname(arg, val)
            if sarg:
                fname += '.' + sarg
        return fname
    print(args, flush=True)
    binary = 'fact-eval/fact_secretbox'
    if args.asm:
        binary += '.asm'
    else:
        binary += '.cref'
    if not args.unopt:
        binary += '.O2'
    proj = angr.Project(binary)

    if args.unopt:
        if not args.asm:
            declassified_verify_branch = 0x403075
        else:
            declassified_verify_branch = 0x404095
    else:
        if not args.asm:
            declassified_verify_branch = 0x4020be
        else:
            declassified_verify_branch = 0x40237e

    fname = '_crypto_secretbox'
    if args.open:
        fname += '_open'
        params = [
            ("m", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
            ("m_len", publicValue(1024, bits=64)),
            ("c", pointerTo(publicArray(1024), 1024)), # XXX should be unconstrained
            ("c_len", publicValue(1024, bits=64)),
        ]
    else:
        params = [
            ("c", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
            ("c_len", publicValue(1024, bits=64)),
            ("m", pointerTo(secretArray(1024), 1024)), # XXX should be unconstrained
            ("m_len", publicValue(1024, bits=64)),
        ]
    params += [
        ("n", pointerTo(publicArray(24), 24)),
        ("k", pointerTo(secretArray(32), 32)),
    ]
    state = funcEntryState(proj, fname, params)
    return proj, state, fname, [declassified_verify_branch]

def arg_to_fname(arg, val):
    sarg = ''
    if isinstance(val, bool):
        if not val:
            sarg = 'no-'
        sarg += arg
    elif isinstance(val, int):
        if val is not None:
            sarg = arg
            sarg += str(val)
    return sarg

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--spec', action='store_true')
    parser.add_argument('--window', type=int, action='store', default=250)
    parser.add_argument('--misforwarding', action='store_true')
    parser.add_argument('--generating-filename', action='store_true')
    parser.add_argument('--guided', action='store_true')
    parser.add_argument('test')

    args, remaining_args = parser.parse_known_args()
    generating_filename = args.generating_filename
    if generating_filename:
        del vars(args)['generating_filename']
        argsd= dict(vars(args))
        del argsd['test']
        del argsd['trace']
        fname = args.test
        fname += globals()[args.test](remaining_args, generating_fname=True)
        for arg in sorted(argsd):
            val = argsd[arg]
            sarg = ''
            if arg == 'misforwarding':
                if args.spec:
                    sarg = 'misfwd' if val else 'basicfwd'
            elif arg == 'spec':
                if val:
                    sarg = 'spec'
                else:
                    sarg = 'ct'
            elif arg == 'window':
                if args.spec:
                    sarg = arg_to_fname(arg, val)
            elif arg == 'guided':
                continue
            else:
                sarg = arg_to_fname(arg, val)
            if sarg:
                fname += '.' + sarg
        if args.trace:
            fname += '.trace'
        print(fname)
        exit(0)
    print(args, flush=True)

    rvals = globals()[args.test](remaining_args)
    proj = rvals[0]
    state = rvals[1]
    fname = rvals[2]
    whitelist = rvals[3]
    path = ''
    if not args.guided:
        if len(rvals) > 4:
            path = rvals[4]
        if not path:
            print('no guiding path for this test case', file=sys.stderr)
            exit(1)
    _spectreSimgr(lambda: (proj, state), [], fname, "explicit", spec=args.spec, misforwarding=args.misforwarding, whitelist=whitelist, window=args.window, trace=args.trace, takepath=path)
