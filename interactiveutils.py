# Useful utilities for interactive use

import angr
from sys import stdout

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
    if not simgr.active:
        print("No active states")
        return
    elif len(simgr.active) > 1:
        print("Please stash all but one active state before using verboseStep")
        return
    oldaddr = simgr.active[0].addr
    simgr.step()
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
    else: print("block {}".format(hex(oldaddr)))
    print("===============")
    describeUpcomingBlock(proj, simgr, asm=asm)

def describeUpcomingBlock(proj, simgr, asm=True):
    """
    asm: see notes on verboseStep
    """
    if not simgr.active:
        print("No active states remaining")
    elif len(simgr.active) > 1:
        print("Multiple resulting states, at {}".format(list(hex(s.addr) for s in simgr.active)))
    else:
        addr = simgr.active[0].addr
        symb = proj.loader.find_symbol(addr, fuzzy=False)
        if symb:
            print("About to execute (top of function {}):".format(symb.name))
        else:
            symb = proj.loader.find_symbol(addr, fuzzy=True)
            if symb:
                print("About to execute (in function {}):".format(symb.name))
            else:
                print("About to execute (unknown function):")
        if asm: showbbASM(proj, addr)
        elif asm is not None: showbbVEX(proj, addr)
        else: print("block {}".format(hex(addr)))
        print("\nCurrently at instruction {}".format(hex(addr)))

def runUntilRetFrom(proj, simgr, calladdr, asm=True):
    """
    calladdr: address of the call instruction (NOT the address of the called function)
    asm: see notes on verboseStep
    """
    def atReturn(candidateAddr): return (candidateAddr > calladdr) and (candidateAddr <= calladdr+5)  # technically a heuristic, but should basically always work
    simgr.run(until=lambda sim: any(atReturn(s.addr) for s in sim.active))
    describeUpcomingBlock(proj, simgr, asm=asm)

def stashAllButFirst(proj, simgr, asm=True):
    """
    Stash all the active states in the simgr except the first.
    asm: see notes on verboseStep
    """
    if not simgr.active:
        print("No active states: nothing to stash")
        return
    first = simgr.active[0]
    simgr.stash(filter_func=lambda s: s is not first)
    describeUpcomingBlock(proj, simgr, asm=asm)

def stashFirst(proj, simgr, asm=True):
    """
    Stash the first active state in the simgr
    asm: see notes on verboseStep
    """
    if not simgr.active:
        print("No active states: nothing to stash")
        return
    first = simgr.active[0]
    simgr.stash(filter_func=lambda s: s is first)
    describeUpcomingBlock(proj, simgr, asm=asm)

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
