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

def verboseStep(proj, simgr, asm=True):
    """
    asm: If True then show blocks as x86 assembly instructions.
        If False then show blocks as VEX IR instructions.
        If None then don't show block contents, only block addresses.
    """
    if len(simgr.active) > 1:
        print("Please stash all but one active state before using verboseStep")
    else:
        oldaddr = simgr.active[0].addr
        simgr.step()
        newaddr = simgr.active[0].addr if simgr.active else None
        oldsymb = proj.loader.find_symbol(oldaddr, fuzzy=False)
        if oldsymb:
            print("Just executed (top of function {}):".format(oldsymb.name))
        else:
            oldsymb = proj.loader.find_symbol(oldaddr, fuzzy=True)
            if oldsymb:
                print("Just executed (in function {}):".format(oldsymb.name))
            else:
                print("Just executed (unknown function):")
        if asm: showbbASM(proj, oldaddr)
        elif asm is not None: showbbVEX(proj, oldaddr)
        else: print("block {}".format(oldaddr))
        print("===============")
        if newaddr is None:
            print("Execution finished")
            return
        newsymb = proj.loader.find_symbol(newaddr, fuzzy=False)
        if newsymb:
            print("About to execute (top of function {}):".format(newsymb.name))
        else:
            newsymb = proj.loader.find_symbol(newaddr, fuzzy=True)
            if newsymb:
                print("About to execute (in function {}):".format(newsymb.name))
            else:
                print("About to execute (unknown function):")
        if asm: showbbASM(proj, newaddr)
        elif asm is not None: showbbVEX(proj, newaddr)
        else: print("block {}".format(newaddr))
        print("\nCurrently at instruction {}".format(hex(newaddr)))

def runUntilRetFrom(simgr, calladdr):
    """
    calladdr: address of the call instruction (NOT the address of the called function)
        Assumes it's a callq or some other 5-byte instruction
    """
    simgr.run(until=lambda s: s.active[0].addr == calladdr+5)

def stashAllButFirst(simgr):
    """
    Stash all the active states in the simgr except the first
    """
    first = simgr.active[0]
    simgr.stash(filter_func=lambda s: s is not first)

def stashFirst(simgr):
    """
    Stash the first active state in the simgr
    """
    first = simgr.active[0]
    simgr.stash(filter_func=lambda s: s is first)

def stepTogether(simgrA, simgrB):
    """
    Shortcut to step a pair of simgrs together.
    Intended for interactive mode, comparing two configurations.
    """
    simgrA.step()
    simgrB.step()
    print("A: {}".format(simgrA.active))
    print("B: {}".format(simgrB.active))

def stashTogether(simgrA, simgrB, addr):
    """
    Stash all states at the given addr in both simgrs.
    Intended for use with stepTogether.
    """
    simgrA.stash(filter_func=lambda s: s.addr==addr)
    simgrB.stash(filter_func=lambda s: s.addr==addr)
