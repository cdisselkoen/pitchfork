# Method stubs (approximations) to make the analysis more tractable

import angr
from taint import taintedUnconstrainedBits
from utils import describeAst
import logging
l = logging.getLogger(__name__)

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

class EVP_PKEY_meth_find_stub(angr.SimProcedure):
    """
    Stub for OpenSSL's EVP_PKEY_meth_find()
    """
    def __init__(self, proj):
        super().__init__()
        self.proj = proj  # keep around a pointer to proj (for symbol resolution)

    #def display_name(self):
        #return "<Stub object for EVP_PKEY_meth_find>"

    def run(self, type_int):
        l.info("stubbing out a call to EVP_PKEY_meth_find")
        # In my current understanding, this method searches through a static list of EVP_PKEY_METHOD objects
        #   looking for one that has its first field equal to the provided `type_int` argument.
        # We simply perform this functionality here rather than symexing the binary search.
        names = [
            "rsa_pkey_meth",
            "dh_pkey_meth",
            "dsa_pkey_meth",
            "ec_pkey_meth",
            "hmac_pkey_meth",
            "cmac_pkey_meth",
            "rsa_pss_pkey_meth",
            "dhx_pkey_meth",
            "scrypt_pkey_meth",
            "tls1_prf_pkey_meth",
            "ecx25519_pkey_meth",
            "ecx448_pkey_meth",
            "hkdf_pkey_meth",
            "poly1305_pkey_meth",
            "siphash_pkey_meth",
            "ed25519_pkey_meth",
            "ed448_pkey_meth",
            "sm2_pkey_meth"
        ]
        possible_meths = (self.proj.loader.find_symbol(name).rebased_addr for name in names)
        for meth in possible_meths:
            if meth is None: continue
            meth_pkey_id = self.state.mem[meth].int32_t
            if self.state.solver.solution(type_int, meth_pkey_id):
                # Since I'm not sure how to fork for each possible return value,
                # for now we just use the first match
                self.state.add_constraints(type_int == meth_pkey_id)
                return meth
        raise ValueError("couldn't find a valid method, type was {}".format(describeAst(type_int)))

def addEVPStubs(proj):
    # for now, just one EVP-related stub
    proj.hook_symbol("EVP_PKEY_meth_find", EVP_PKEY_meth_find_stub(proj))
