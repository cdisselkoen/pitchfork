import claripy
from taint import is_tainted

def isAst(x):
    return isinstance(x, claripy.ast.Base)

def describeAst(ast, checkTaint=True):
    return hex(ast) if not isAst(ast) \
            else "{}".format(ast) if not checkTaint \
            else "{} (TAINTED)".format(ast) if is_tainted(ast) \
            else "{} (untainted, but with annotations {})".format(ast, ast.annotations) if hasattr(ast, 'annotations') and ast.annotations \
            else "{} (untainted)".format(ast)

def canonicalizeAdd(a):
    canon = a
    ctotal = 0
    if isinstance(a, int):
        return a
    if a.op == '__add__':
        canon = a.args[0]
        for arg in a.args[1:]:
            if arg.op == 'BVV':
                ctotal += arg.args[0]
            else:
                canon += arg
        if ctotal:
            canon += ctotal
    return canon

def isDefinitelyEqual(a,b):
    """
    Does 'a' definitely equal 'b', i.e., is it impossible for them to be not equal.

    this implementation is pretty conservative, and errs on the side of returning False.
        (it will never mistakenly return True, but may mistakenly return False)
    To be less conservative, use isDefinitelyEqual_Solver() (below)
    """
    if isinstance(a, int) and isinstance(b, int): return a == b
    if isAst(a) or isAst(b): return (canonicalizeAdd(a) == canonicalizeAdd(b)).is_true()
    raise ValueError("not sure what to do about {} and {} with types {} and {}".format(a,b,type(a),type(b)))

def isDefinitelyEqual_Solver(state, a, b):
    """
    Does 'a' definitely equal 'b', i.e., is it impossible for them to be not equal.

    More expensive than isDefinitelyEqual() (above), because it takes into account the
        current context.
    May catch some cases where 'a' definitely equals 'b' in the current context but
        isDefinitelyEqual() returned False.
    """
    if isinstance(a, int) and isinstance(b, int): return a == b
    return not state.solver.satisfiable(extra_constraints=[a != b])

def isDefinitelyNotEqual(a,b):
    """
    Does 'a' definitely not equal 'b', i.e., is it impossible for them to be equal.

    this implementation is pretty conservative, and errs on the side of returning False.
        (it will never mistakenly return True, but may mistakenly return False)
    To be less conservative, use isDefinitelyNotEqual_Solver() (below)
    """
    if isinstance(a, int) and isinstance(b, int): return a != b
    if isAst(a) or isAst(b): return (a != b).is_true()
    raise ValueError("not sure what to do about {} and {} with types {} and {}".format(a,b,type(a),type(b)))

def isDefinitelyNotEqual_Solver(state, a, b):
    """
    Does 'a' definitely not equal 'b', i.e., is it impossible for them to be equal.

    More expensive than isDefinitelyNotEqual() (above), because it takes into account
        the current context.
    May catch some cases where 'a' definitely does not equal 'b' in the current context
        but isDefinitelyNotEqual() returned False.
    """
    if isinstance(a, int) and isinstance(b, int): return a != b
    return not state.solver.satisfiable(extra_constraints=[a == b])
