# !/usr/bin/env python
# coding=UTF-8
# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

import binaries     # Object class for storing and manipulating binaries
import static       # Object class with all static features to be tested
import ml           # Machine Learning for training and testing binaries
import dynamic
# import sys
import ConfigParser # Configuration file for user
import argparse     # Parse received arguments
import pickle
import os


def retrieval():
    # Use argparse to get argument files, https://docs.python.org/3/library/argparse.html
    # Files should contain paths to goodware, malware and/or suspicious binaries
    parser = argparse.ArgumentParser(description = 'Forsite malware classifier.',usage='%(prog)s [-hgms] [ARGS]')
    parser.add_argument('-g','--goodware',type=argparse.FileType('r'),metavar='',help="Text file with benign binaries path's")
    parser.add_argument('-m','--malware',type=argparse.FileType('r'),metavar='',help="Text file with malicious binaries path's")
    parser.add_argument('-s','--suspicious',type=argparse.FileType('r'),metavar='',help="Text file with unknown binaries path's")
    args = parser.parse_args()

    goodware = []
    malware = []
    suspicious = []

    # Opens config file with user configurations
    config = ConfigParser.RawConfigParser()
    config.read('forsite.conf')

    try:
        for path in args.goodware:
            goodware.append(binaries.Binary(path[:-1],"goodware"))
    except:
        print('ERROR: \{MAIN.PY\} Forsite set to validation in configuration file. Lack of text file with benign paths.')
        parser.print_help()
        exit(1)
    try:
        for path in args.malware:
            malware.append(binaries.Binary(path[:-1],"malware"))
    except:
        print('ERROR: \{MAIN.PY\} Forsite set to validation in configuration file. Lack of text file with malware paths.')
        parser.print_help()
        exit(1)

    if(config.get('Classifier','Mode') == 'Testing'):
        try:
            for path in args.suspicious:
                suspicious.append(binaries.Binary(path[:-1]))
        except:
            print('ERROR: \{MAIN.PY\} Forsite set to testing in configuration file. Lack of text file with unclassified paths.')
            parser.print_help()
            exit(1)

    #TODO: Possible error with lack of else.
    return goodware,malware,suspicious


##############################################
#                                            #
#                                            #
#                   Main                     #
#                                            #
#                                            #
##############################################

# Lists for holding binaries
goodware   = []
malware    = []
suspicious = []

# Retrieves binary from arguments
goodware,malware,suspicious = retrieval()

# Opens config file with user configurations
config = ConfigParser.RawConfigParser()
config.read('forsite.conf')

##############################################
#                                            #
#                  Features                  #
#                                            #
##############################################


sd = static.StaticDiscrete()
sc = static.StaticContinuous()
# dnd = dynamic.DynamicDiscrete()
dyn = dynamic.Dynamic()

if(config.get('Classifier','Analysis') == 'Static'):
    # Perform static analysis on the samples
    for binary in (goodware + malware + suspicious):
        # Opens saved binary with features, if exists.
        if (binary.pickleLoad() == 1):
            continue #POSSIBLE ERROR SOURCE!
        else:
            # Runs all discrete features
            sd.runAll(binary)
            # Runs all continuous features
            sc.runAll(binary)
            # Save the binary
            binary.pickleDump()

elif(config.get('Classifier','Analysis') == 'Dynamic'):
    for binary in (goodware + malware + suspicious):
        # Opens saved binary with features, if exists.
        if (binary.dynamicLoad() == 1):
            continue #POSSIBLE ERROR SOURCE!
        else:
            # Runs all discrete features
            dyn.runAll(binary)
            # Runs all continuous features
            # dnc.runAll(binary)
            # Save the binary
            binary.dynamicDump()


for binary in (goodware+malware+suspicious):
    binary.printBinary()


##############################################
#                                            #
#             Machine Learning               #
#                                            #
##############################################

# Select machine learning algorithm
if(config.get('Classifier','Algorithm') == 'SVM'):
    ml1 = ml.Svm(goodware+malware)
elif(config.get('Classifier','Algorithm') == 'RandomForest'):
    ml1 = ml.RandomForest(goodware+malware)
elif(config.get('Classifier','Algorithm') == 'MLP'):
    ml1 = ml.MLP(goodware+malware)
else:
    print('Error: Invalid ml algorithm at classifier.conf.')
    exit(0)

#This can go into validation mode only. Futurely.
# ml1.createKFold()

if(config.get('Classifier','Mode') == 'Validation'):
    if(config.get('Classifier','Run') == 'Single'):
        ml1.singleRun()
    elif(config.get('Classifier','Run') == 'Multiple'):
        ml1.multipleRun()
elif(config.get('Classifier','Mode') == 'Testing'):
    ml1.trainingTesting(goodware,malware,suspicious)
