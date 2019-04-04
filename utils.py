# Useful utilities, either to use interactively, or as display subroutines for other functions

import claripy
from taint import is_tainted
from sys import stdout

def isAst(x):
    return isinstance(x, claripy.ast.Base)

def describeAst(ast, checkTaint=True):
    return hex(ast) if not isAst(ast) \
            else "{}".format(ast) if not checkTaint \
            else "{} (TAINTED)".format(ast) if is_tainted(ast) \
            else "{} (untainted, but with annotations {})".format(ast, ast.annotations) if hasattr(ast, 'annotations') and ast.annotations \
            else "{} (untainted)".format(ast)


def showbbASM(proj, bbaddr, file=stdout):
    """
    Show the x86 assembly for the basic block at the given address
    file: where to print the output (must be an open file object, defaults to stdout)
    """
    file.write(str(proj.factory.block(bbaddr).capstone)+'\n')

def showbbVEX(proj, bbaddr, file=stdout):
    """
    Show the VEX IR for the basic block at the given address
    file: where to print the output (must be an open file object, defaults to stdout)
    """
    file.write(str(proj.factory.block(bbaddr).vex)+'\n')

def showBBHistory(proj, state, asm=True, file=stdout):
    """
    Show the entire history of basic blocks executed by the given state.
        Note: shows the entire basic block, even if execution jumped out early.
        (angr/VEX has a very different definition of "basic block" than you might think -
            e.g. conditional jumps do not end basic blocks, only calls and unconditional ones.)
        Look at the next basic block address to determine where execution left the current basic block.
    asm: if True then show each block as x86 assembly instructions.
        If False then show each block as VEX IR instructions.
        If None then don't show block contents, only block addresses.
    file: where to write the history (must be an open file object, defaults to stdout)
    """
    for bbaddr in state.history.bbl_addrs:
        file.write("Basic block {}{}\n".format(hex(bbaddr), ":" if asm is not None else ""))
        if asm: showbbASM(proj, bbaddr, file=file)
        elif asm is not None: showbbVEX(proj, bbaddr, file=file)
    file.write("Currently at instruction {}\n".format(hex(state.addr)))

def dumpHistories(proj, states, asm=True):
    """
    states: an iterable of states
    asm: see notes on showBBHistory

    Dump the histories of each of the states into files "history1.txt", "history2.txt", etc
    """
    for (i,state) in enumerate(states):
        with open('history'+str(i)+'.txt', 'w') as f:
            showBBHistory(proj, state, asm=asm, file=f)
