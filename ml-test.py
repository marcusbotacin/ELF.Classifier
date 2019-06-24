# !/usr/bin/env python
# coding=UTF-8

# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

import binaries
import ml
import sys
import static

svm = ml.Svm()

goodware = []
malware = []
suspicious = []

goodware.append(binaries.Binary(sys.argv[1],"goodware"))
malware.append(binaries.Binary(sys.argv[2],"malware"))
suspicious.append(binaries.Binary(sys.argv[3]))


for binary in (goodware + malware + suspicious):
    #binary.flist.append(static.Linkage(binary))
    binary.flist.append(static.UpxPresent(binary))

svm.train(goodware,malware)

svm.test(suspicious)
