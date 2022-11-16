# CS527-Symbolic-Execution
Lab 2 for CS527

Prof Website: https://yueduan.github.io/cs527_lab2.html

Instructions: 

1. Introduction
In this lab, you will implement a simple tool that collects some statistics about a binary executable file and performs symbolic execution, using an open-source symbolic execution engine named Angr. Your tool takes as input a binary file (given by the instructor), and outputs three things: 1). interprocedural control-flow graph in a dot file; 2). statistics about the binary; 3). correct inputs to reach some target places.
You will be graded by reports. Randomly seletected students (~10%) are expected to explain your code and demonstrate that you understand what you did and why you did it that way.

2. Getting started

a) Download the binary.

b) Download Angr and configure it up. Please refer to this tutorial on how to install.


3. Assignment
a) Control-flow graph generation. Given a binary, your job is to output the interprocedural control-flow graph for the entire binary into a dot format file. Moreover, you need to print out the following numbers: 1). number of nodes in the graph; 2). number of edges in the graph; 3) number of different instruction types.

b) Symbolic Execution. Given a binary, your job is to write a script to 1). find addresses for all 'put' functions; 2). feed the addresses as targets to the symbolic execution engine; 3). perform symbolic execution to generate correct inputs to trigger these 'put' functions.


4. What to submit
You need to submit a report that includes the following:

    Screenshot of your code (only your code)
    Detailed explanation about the code
    Screenshots about how you run the code and results (2 files: cfg dot file, a file that contains statistics and correct inputs)


My Notes:

This is a implementation for "Angr" a platform-agnostic binary analysis framework.

This project can be found at https://github.com/angr/angr

"Test" is the file that will be pushed through Angr.

