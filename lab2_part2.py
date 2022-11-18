#!/usr/bin/env python
# coding: utf-8

import sys
import angr

##from object dump file, 1070 is the info for the call "puts" <puts@plt>
putsID = "1070"

proj = angr.Project("./test", load_options={'auto_load_libs': False})
#print(proj)

cfg = proj.analyses.CFGFast(data_references=True, normalize=True)
#print(cfg.graph)

nodelist = list(cfg.graph.nodes())
edgelist = list(cfg.graph.edges())

numofnodes = len(nodelist)
numofedges = len(edgelist)

for node in nodelist:
    if node.block is None:
        continue
    for insn in node.block.capstone.insns:
        mne = insn.mnemonic
        if mne == 'call':
            if insn.op_str.endswith(putsID):
                addr_target = insn.address
                
                print("This is the Hex value of the Target Address:", hex(addr_target))
                
                initial_state = proj.factory.entry_state()
                simulation = proj.factory.simgr(initial_state, resilience="False")
                #print(initial_state)
                
                simulation.explore(find=addr_target)
                
                if simulation.found:
                    solution_state = simulation.found[0]
                    solution = solution_state.posix.dumps(sys.stdin.fileno())
                    print("Success! Solution is: {}".format(solution.decode("utf-8")))
                
                else:
                    raise Exception("Could not find the solution")
