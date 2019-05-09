# Method stubs (approximations) to make the analysis more tractable

import angr
from taint import taintedUnconstrainedBits
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
