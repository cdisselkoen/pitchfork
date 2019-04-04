import angr
import claripy

class TaintedAnnotation(claripy.Annotation):
    """
    Annotation for doing taint-tracking in angr.
    """
    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        srcAnnotations = list(src.annotations)
        if len(srcAnnotations) == 0: return None
        elif len(srcAnnotations) == 1: return srcAnnotations[0]
        else: raise ValueError("more than one annotation: {}".format(srcAnnotations))

def taintedUnconstrainedBits(state, name, bits):
    """
    name: a name for the BVS
    bits: how many bits long
    """
    return state.solver.Unconstrained(name, bits, key=("tainted_"+name,), eternal=False, annotations=(TaintedAnnotation(),))

def is_tainted(ast):
    return _is_immediately_tainted(ast) or any(_is_immediately_tainted(v) for v in ast.leaf_asts())

def _is_immediately_tainted(ast):
    return any(isinstance(a, TaintedAnnotation) for a in ast.annotations)
