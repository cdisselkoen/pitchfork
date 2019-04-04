import angr
from taint import is_tainted, taintedUnconstrainedBits

import logging
l = logging.getLogger(__name__)

class IROpHook(angr.SimStatePlugin):
    """
    Allows hooking the computation of operations performed in the symbolic execution.
    (requires our fork of angr to actually respect the hook)
    """
    def do_op(self, state, irop, args):
        """
        irop: an angr.vex.engines.SimIROp
        args: arguments to irop, which will all be claripy objects (instances of claripy.ast.Base)

        return: claripy object to use as the result of the operation;
            or None to refrain from hooking the operation, and let angr proceed normally
        """
        if any(is_tainted(a) for a in args):
            #l.debug("Replacing operation {} on {} with unconstrained secret".format(irop, args))
            return taintedUnconstrainedBits(state, "secret", irop._output_size_bits)
        return None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return IROpHook()
