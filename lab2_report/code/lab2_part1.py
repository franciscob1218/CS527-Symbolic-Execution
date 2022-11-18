#!/usr/bin/env python
# coding: utf-8

import angr 
import os
import argparse
import monkeyhex
from angrutils import *
import subprocess
import graphviz

proj = angr.Project("./test", load_options={'auto_load_libs': False})

cfg = proj.analyses.CFGFast(data_references=True, normalize=True)

nodelist = list(cfg.graph.nodes())
edgelist = list(cfg.graph.edges())

numofnodes = len(nodelist)
numofedges = len(edgelist)

nodelist1 = [node for node in list(cfg.graph.nodes()) if node.block !=None]
print("Number of nodes in the graph:", numofnodes)
print("Number of edges in the graph:", numofedges)

main = proj.loader.main_object.get_symbol("main")
#print(main)

start_state = proj.factory.blank_state(addr=main.rebased_addr)
#print(start_state)
 
plot_cfg(cfg, "binary_test_cfg", format="png", asminst=True, remove_imports=True, remove_path_terminator=True)  

plot_cfg(cfg, "binary_test_cfg", format="dot", asminst=True, remove_imports=True, remove_path_terminator=True)  

allIns = set()
for node in nodelist1:
    #print(node)
    for ins in ((node.block.disassembly.insns)):
        #print(ins.mnemonic)
        allIns.add(ins.mnemonic)

print("These are all of the unique Instructions in the Binary:", allIns)

print("Number of different instruction types:", len(allIns))
