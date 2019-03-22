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

class MySolver(angr.state_plugins.SimSolver):
    """
    A subclass just to add a single new accessor we need.
    """

    def leaves(self, v):
        """
        Given an AST, iterate over all the BVS leaves in the tree which are registered.
        """
        reverse_mapping = {next(iter(var.variables)): var for k,var in self.eternal_tracked_variables.items()}
        reverse_mapping.update({next(iter(var.variables)): var for k,var in self.temporal_tracked_variables.items() if k[-1] is not None})

        for var in v.variables:
          if var in reverse_mapping:
            yield reverse_mapping[var]

    # Entirely copied from SimSolver's method, just constructs a MySolver instead of a SimSolver
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return MySolver(solver=self._solver.branch(),
                        all_variables=self.all_variables,
                        temporal_tracked_variables=self.temporal_tracked_variables,
                        eternal_tracked_variables=self.eternal_tracked_variables)

# use MySolver instances instead of SimSolver
MySolver.register_default('solver')
