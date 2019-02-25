import angr
import claripy
import pyvex

from oob import OOBStrategy, can_be_oob

import logging
l = logging.getLogger(name=__name__)

class SpectreState(angr.SimStatePlugin):
    """
    State tracking for Spectre gadget vulnerability detection
    """

    def __init__(self, armed=False):
        super().__init__()
        self._armed = armed
        self.violation = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpectreState(armed=self._armed)

    def arm(self, state):
        """
        Setup hooks and breakpoints to perform Spectre gadget vulnerability detection.
        Also set up concretization to ensure addresses are always made to be OOB when possible.
        """
        state.inspect.b('mem_read',  when=angr.BP_AFTER, condition=_tainted_read, action=detected_spectre_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_tainted_write, action=detected_spectre_write)
        state.inspect.b('exit', when=angr.BP_BEFORE, condition=_tainted_branch, action=detected_spectre_branch)

        state.memory.read_strategies.insert(0, OOBStrategy())
        state.memory.write_strategies.insert(0, OOBStrategy())

        # In the future, this code will be used to replace all 'solver' state plugins with our 'MySolver'
        # but this doesn't work correctly, so for now we just patched angr's SimSolver to provide the leaves() method we need
        #old_solver = state.solver
        #state.release_plugin('solver')
        #state.register_plugin('solver', MySolver(old_solver))

        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        state.options.add(angr.options.SPECIAL_MEMORY_FILL)
        state._special_memory_filler = oob_memory_fill
        state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed

def oob_memory_fill(name, bits, state):
    return state.solver.Unconstrained(name, bits, key=("OOB_"+name,), eternal=False, annotations=(TaintedAnnotation(),))

# Call during a breakpoint callback on 'mem_read'
def _tainted_read(state):
    addr = state.inspect.mem_read_address
    expr = state.inspect.mem_read_expr
    l.debug("read {} (with annotations {}) from {} (with annotations {})".format(expr, expr.annotations, addr, addr.annotations))
    if _is_tainted(state, addr):
        return can_be_oob(state, addr, state.inspect.mem_read_length)
    else:
        return False

# Call during a breakpoint callback on 'mem_write'
def _tainted_write(state):
    addr = state.inspect.mem_write_address
    if _is_tainted(state, addr):
        return can_be_oob(state, addr, state.inspect.mem_write_length)
    else:
        return False

# Call during a breakpoint callback on 'exit' (i.e. conditional branch)
def _tainted_branch(state):
    return _is_tainted(state, state.inspect.exit_guard)

def _is_tainted(state, ast):
    l.debug("checking if {} (with annotations {} and leaves {}) is tainted".format(ast, ast.annotations, list(state.solver.leaves(ast))))
    #assert isinstance(state.solver, MySolver)
    return _is_immediately_tainted(ast) or any(_is_immediately_tainted(v) for v in state.solver.leaves(ast))

def _is_immediately_tainted(ast):
    return ast.uninitialized or any(isinstance(a, TaintedAnnotation) for a in ast.annotations)

def detected_spectre_read(state):
    print("\n!!!!!!!! UNSAFE READ !!!!!!!!\n  Address {}\n  Value {}\n  args were {}\n  constraints were {}\n  annotations were {}\n".format(
        state.inspect.mem_read_address, state.inspect.mem_read_expr, state.globals['args'], state.solver.constraints, state.inspect.mem_read_expr.annotations))
    state.spectre.violation = (state.inspect.mem_read_address, state.inspect.mem_read_expr)

def detected_spectre_write(state):
    print("\n!!!!!!!! UNSAFE WRITE !!!!!!!!\n  Address {}\n  Value {}\n  args were {}\n  constraints were {}\n  annotations were {}\n".format(
        state.inspect.mem_write_address, state.inspect.mem_write_expr, state.globals['args'], state.solver.constraints, state.inspect.mem_write_expr.annotations))
    state.spectre.violation = (state.inspect.mem_write_address, state.inspect.mem_write_expr)

def detected_spectre_branch(state):
    print("\n!!!!!!!! UNSAFE BRANCH !!!!!!!!\n  Branch Address {}\n  Branch Target {}\n  Guard {}\n  args were {}\n  constraints were {}\n  annotations were {}\n".format(
        hex(state.addr), state.inspect.exit_target, state.inspect.exit_guard, state.globals['args'], state.solver.constraints, state.inspect.exit_guard.annotations))
    state.spectre.violation = (state.addr, state.inspect.exit_target, state.inspect.exit_guard)

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
        return src.annotation

class MySolver(angr.state_plugins.SimSolver):
    """
    A subclass just to add a single new accessor we need.
    """
    def __init__(self, simsolver):
        """
        Pass the SimSolver instance which you want to turn into a MySolver.
        """
        super().__init__(solver = simsolver._stored_solver,
                          all_variables = simsolver.all_variables,
                          temporal_tracked_variables = simsolver.temporal_tracked_variables,
                          eternal_tracked_variables = simsolver.eternal_tracked_variables)

    def leaves(self, v):
        """
        Given an AST, iterate over all the BVS leaves in the tree which are registered.
        """
        reverse_mapping = {next(iter(var.variables)): var for k,var in self.eternal_tracked_variables.items()}
        reverse_mapping.update({next(iter(var.variables)): var for k,var in self.temporal_tracked_variables.items() if k[-1] is not None})

        for var in v.variables:
          if var in reverse_mapping:
            yield reverse_mapping[var]
