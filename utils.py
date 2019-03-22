# Useful utilities, either to use interactively, or as display subroutines for other functions

import claripy
from taint import is_tainted

def isAst(x):
    return isinstance(x, claripy.ast.Base)

def describeAst(state, ast, checkTaint=True):
    return hex(ast) if not isAst(ast) \
            else "{}".format(ast) if not checkTaint \
            else "{} (TAINTED)".format(ast) if is_tainted(state, ast) \
            else "{} (untainted, but with annotations {})".format(ast, ast.annotations) if ast.annotations \
            else "{} (untainted)".format(ast)

def showbbASM(proj, bbaddr):
    """
    Show the x86 assembly for the basic block at the given address
    """
    proj.factory.block(bbaddr).capstone.pp()

def showbbVEX(proj, bbaddr):
    """
    Show the VEX IR for the basic block at the given address
    """
    proj.factory.block(bbaddr).vex.pp()

def showBBHistory(proj, state, asm=True):
    """
    Show the entire history of basic blocks executed by the given state.
        Note: shows the entire basic block, even if execution jumped out early.
        (angr/VEX has a very different definition of "basic block" than you might think -
            e.g. conditional jumps do not end basic blocks, only calls and unconditional ones.)
        Look at the next basic block address to determine where execution left the current basic block.
    asm: if True then show each block as x86 assembly instructions.
        If False then show each block as VEX IR instructions.
        If None then don't show block contents, only block addresses.
    """
    for bbaddr in state.history.bbl_addrs:
        print("Basic block {}{}".format(hex(bbaddr), ":" if asm is not None else ""))
        if asm: showbbASM(proj, bbaddr)
        elif asm is not None: showbbVEX(proj, bbaddr)
    print("Currently at instruction {}".format(hex(state.addr)))
