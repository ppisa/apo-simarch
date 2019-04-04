#!/usr/bin/python
# -*- coding: utf-8 -*-

# sys.argv[0] - jmeno skriptu
# sys.argv[1] - task variant
# sys.argv[2] - mutuations pattern


import numbers
import collections
import sys
import simarch

if __name__ == '__main__':

    with open('instruction.cpp.new', 'w') as outfile, open('instruction.cpp', 'r') as infile:
         for line in infile:
             if '    {"' != line[:6]:
                 outfile.write(line)
             else:
                 e = line.index('"', 6)
                 if e == -1:
                     exit(1)
                 inst = line[6:e]
                 e = len(line) - line[::-1].index(',')
                 inst = inst.lower()
                 outfile.write(line[0:e])

                 if inst not in simarch.instdesbyname:
                     sys.stderr.write('no description for "%s"\n'%(inst))
                     outfile.write(' nullptr, 0, 0')
                 else:
                     des = simarch.instdesbyname[inst][0]
                     outfile.write(' {')
                     for arg in des.args:
                         outfile.write('"'+ arg +'", ')
                     outfile.write("nullptr}, 0x%08x, 0x%08x,"%(des.match,des.mask))

                 outfile.write(line[e:])
                 
                 
