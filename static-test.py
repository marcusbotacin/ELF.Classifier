# !/usr/bin/env python
# coding=UTF-8

# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

import sys
import binaries
import static

binary_list = []

sf = static.StaticContinuous()
# sf = static.StaticDiscrete()


binary_list.append(binaries.Binary(sys.argv[1],[]))

for binary in binary_list:
    print("Looping ...")
    #binary.flist.append(sf.Linkage(binary))
    #binary.flist.append(sf.UpxPresent(binary))
    #binary.flist.append(sf.Fork(binary))
    binary.clist.append(sf.numSections(binary))
    binary.clist.append(sf.numSymbols(binary))
    binary.clist.append(sf.numRelocations(binary))
    binary.clist.append(sf.numDebugSection(binary))

for binary in binary_list:
    print(binary.elf)
    print(binary.clist)
