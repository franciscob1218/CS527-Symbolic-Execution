# README:

Author: Francisco Barba Cuellar

GitHub: @franciscob1218

Team: solo

## Introduction to the lab:

In this lab: you will implement a simple tool that collects some statistics about a binary executable file and performs symbolic execution, using an open-source symbolic execution engine named Angr.

 Your tool takes as input a binary file (given by the instructor), and outputs three things: 

1. Intraprocedural control-flow graph in a dot file
2. statistics about the binary
3. correct inputs to reach some target places.

## Getting started: Environment Setup & Installation:

I first created a new GitHub repo located at: [https://github.com/franciscob1218/CS527-Symbolic-Execution](https://github.com/franciscob1218/CS527-Symbolic-Execution). I needed to setup and configure angr, so I followed the tutorial located on the angr home page: [https://docs.angr.io/introductory-errata/install](https://docs.angr.io/introductory-errata/install). 

The first time I had decided to install angr using git clone and installing it with the “setup.py” that completely destroyed my original python libs causing me to need to reload the VM from scratch. The best recommendation I can give is install angr after the virtualenv has been started

I ran the  following commands to install the needed dependencies:

```bash
$ sudo apt-get install python3-pip python3-dev libffi-dev build-essevntial virtualenv virtualenvwrapper graphviz
```

This worked great, the second time around.

Then I tried to run:

```bash
$ mkvirtualenv --python=$(which python3) angr && pip install angr
```

This became a issue because “mkvirtualenv” was not a recognized command in the bash. I googled around a bit and found this website: [https://computingforgeeks.com/fix-mkvirtualenv-command-not-found-ubuntu/](https://computingforgeeks.com/fix-mkvirtualenv-command-not-found-ubuntu/). This taught me how to confirm the location of the “virtualenvwrapper.sh”

```bash
$ sudo find / -name virtualenvwrapper.sh
>> /usr/share/virtualenvwrapper/virtualenvwrapper.sh

#adding the location to the 
$ vim `~/.bashrc
>> source '/usr/share/virtualenvwrapper/virtualenvwrapper.sh'

#then running * to create the command:
$ source ~/.bashrc
>> Done
```

After this the command above worked and was able to start a python virtualenv. After that the command above also installed augr on the “augr_virtualenv”

Once I was in the virtualenv and had angr installed There were some pip3 libraries I needed to Install.

```bash
$ pip3 install angr-utils monkeyhex graphviz jupyterlab
```

angrutils will help formatting from a cmd output to a visual aid. monkeyhex changes the output to cmd to display a hex number. JupyterLabs, I found that running this again and again would be tiresome and I enjoy the notebook executions more.

After all the Installation, to get into and start the env we do:

```bash
$ workon angr
$ jupyter-lab
```

# Coding Explained:

## LAB#2 Part 1:

### Instruction: Control-flow graph generation.

Given a binary, your job is to output the intraprocedural control-flow graph for the entire binary into a dot format file. Moreover, you need to print out the following numbers:

1. number of nodes in the graph
2. number of edges in the graph
3. number of different instruction types

### Code explained:

```python
import angr             #This is angr the main program that we are going to be using
import os               #This is a module that allows us to call Operating System info
import argparse         #This is a TA recommendation.
import monkeyhex        #This is a module that changes returns into their HEX Values
from angrutils import * #This is the main angr extention lib it helps with creating CFGs
import subprocess       #This is used in angrutils and required
import graphviz         #This is a module that is used for the graphic visualization of the CFGs

proj = angr.Project("./test", load_options={'auto_load_libs': False})
#This is the main method for adding a binary to a angr Project.

cfg = proj.analyses.CFGFast(data_references=True, normalize=True)
#This is a function that calls CFGFast from the project.analyses method

nodelist = list(cfg.graph.nodes())
edgelist = list(cfg.graph.edges())
#Loading cfg.graph information into a list based on the criteria. These put all the "nodes" and "edges" into a list format.

numofnodes = len(nodelist)
numofedges = len(edgelist)
#These ints are storing the length of the nodelist adn edgelist

nodelist1 = [node for node in list(cfg.graph.nodes()) if node.block !=None]
#This removes nodes from the list whose blocks lead to 'None'

print("number of nodes in the graph:", numofnodes)
print("number of edges in the graph:", numofedges)
#These print out the length of the nodes and edges lists

main = proj.loader.main_object.get_symbol("main")
#This grabs the main_object address based on the symbol in this case the main object
#print(main)

start_state = proj.factory.blank_state(addr=main.rebased_addr)
#This loads a fresh new simulation in a blank state at the stated address. In this case that address is the main starting address for the test binary
#print(start_state)
 
plot_cfg(cfg, "binary_test_cfg", format="png", asminst=True, remove_imports=True, remove_path_terminator=True) 
#plot_cfg is a method from angrutils and is a easy way of generating a CFG

plot_cfg(cfg, "binary_test_cfg", format="dot", asminst=True, remove_imports=True, remove_path_terminator=True)
#This is the same plot_cfg except the "format" attribute is different and asks for the creation of a DOT file instead of a PNG  

allIns = set()
#This is a set() essentially a python dictionary but dublicates are not allowed.

for node in nodelist1: #This is a forloop that iterates over nodelist1 for every node in the list 
    #print(node)
    for ins in ((node.block.disassembly.insns)):
		#This is a forloop that iterates node.block.disassembly.insns (This is method that dissassembles a block and shows all of the instructions in a given block) for each instruction in the block.
        #print(ins.mnemonic)
        allIns.add(ins.mnemonic)
				#This adds the current instruction being checks to the allIns set(). And .mnemonic is a attribute that shows just the actual instruction. No need to check for dublicates because of the set() type, it can not have duplicates.

print("These are all of the unique Instructions in the Binary:", allIns)
#This prints the set() allIns.

print("Number of different instruction types:", len(allIns))
#This prints the length of the set() allIns.
```

## LAB#2 Part 2:

### Instruction:

Given a binary, your job is to write a script to:

1. find addresses for all 'put' functions.
2. feed the addresses as targets to the symbolic execution engine.
3. perform symbolic execution to generate correct inputs to trigger these 'put' functions.

### Code explained:

```python
import sys   #This is a module that will allow us to use stdout needed for the last command
import angr  #This is angr the main program that we are going to be using

#from object dump file, 1070 is the info for the call "puts" <puts@plt>
putsID = "1070"

proj = angr.Project("./test", load_options={'auto_load_libs': False})
#This is the main method for adding a binary to a angr Project.
#print(proj)

cfg = proj.analyses.CFGFast(data_references=True, normalize=True)
#This is a function that calls CFGFast from the project.analyses method
#print(cfg.graph)

nodelist = list(cfg.graph.nodes())
edgelist = list(cfg.graph.edges())
#Loading cfg.graph information into a list based on the criteria. These put all the "nodes" and "edges" into a list format.

numofnodes = len(nodelist)
numofedges = len(edgelist)
#These ints are storing the length of the nodelist adn edgelist
for node in nodelist:
#This is a forloop that iterates over nodelist of each node in the list

    if node.block is None:
		#This is a if statement that checks if the given node leads to None on its Block
        continue

    for insn in node.block.capstone.insns:
		#if the Node has a None in its block then this forloop will iterate all of the instructions in the block
        mne = insn.mnemonic
				#this will take the given node instruction and place its mnemonic name into the variable 'mne'

        if mne == 'call':
				#This will check is the given mnemonic name is equivallent to 'call'

            if insn.op_str.endswith(putsID):
						#This will then check if the given instruction, that already matches in mnemonic value, also matches the given ID (address) from the object_dump done at the begining. This number is 1070
                addr_target = insn.address
								#If this matches then the given instruction is labeled as the target addr
                
                print("This is the Hex value of the Target Address:", hex(addr_target))
								#This will print out the Hex value of the target address
                
                initial_state = proj.factory.entry_state()
								#This initializes a variable that stores the binaries starting address

                simulation = proj.factory.simgr(initial_state)
								#This initializes a new simulation from the simulation manager at a given initial state, in this case we want it to start at where the binary starts
                #print(initial_state)
                
                simulation.explore(find=addr_target)
								#This will run through all of the blocks from a given entry point and we ask why don’t you recursively look at the program tree and tell me if you find a way to this address.
                
                if simulation.found:
								#This if statement checks to see if there is ANY value stored at the simulation.found method, given there is a value if continues on.
                    solution_state = simulation.found[0]
										#This will mark the solution found at [0] as variable solution_state.

                    solution = solution_state.posix.dumps(sys.stdin.fileno())
										#This prints the solution state found to stdin.

                    print("Success! Solution is: {}".format(solution.decode("utf-8")))
										#This prints out the solution, decoded into utf-8.
                
                else:
                    raise Exception("Could not find the solution")
										#If no solution is found then this exception is raised letting us know that a solution was not found
								
								#This results in 2 solutions: 0000003214 and ********** (a random 10 digitnumber depending on memory)
```