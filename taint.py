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
    return state.solver.Unconstrained(name, bits, key=("OOB_"+name,), eternal=False, annotations=(TaintedAnnotation(),))

def is_tainted(state, ast):
    #l.debug("checking if {} (with annotations {} and leaves {}) is tainted".format(ast, ast.annotations, list(state.solver.leaves(ast))))
    #if _is_immediately_tainted(ast):
        #l.debug("{} is immediately tainted".format(ast))
        #return True
    #if any(_is_immediately_tainted(v) for v in state.solver.leaves(ast)):
        #l.debug("one of the leaves {} is tainted".format(list(state.solver.leaves(ast))))
        #return True
    #return False
    return _is_immediately_tainted(ast) or any(_is_immediately_tainted(v) for v in state.solver.leaves(ast))

def _is_immediately_tainted(ast):
    #if any(isinstance(a, TaintedAnnotation) for a in ast.annotations):
        #l.debug("one of the annotations {} is tainted".format(list(ast.annotations)))
        #return True
    #return False
    return any(isinstance(a, TaintedAnnotation) for a in ast.annotations)
