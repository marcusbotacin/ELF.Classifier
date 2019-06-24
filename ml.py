# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

import binaries         # Object class for handling binaries
import ConfigParser     # Configuration file for user
import dm               # Data metrics object
import sys
import os

# Machine learning algorithms
from sklearn                 import svm
from sklearn.model_selection import KFold
from sklearn.ensemble        import RandomForestClassifier
from sklearn.neural_network  import MLPClassifier

# Parent class for different machine learning algorithms
class MachineLearing:
    def __init__(self,samples):
        self.samples = samples  # List of binary samples
        self.clf = None         # Classifier object
        # self.clf_list = []
        self.kf = KFold(n_splits=2,shuffle=True,random_state=1)  # KFold object
        self.it_metrics = []    # Data for each split
        self.avrg_metrics = None  # Average Data

    def createKFold(self):
        N_SPLITS = 2 # Designed as DEFAULT (To be made adjustable via config file)
        self.kf = KFold(n_splits=N_SPLITS,shuffle=True,random_state=1)
        return

    def singleRun(self):
        for train_index,test_index in self.kf.split(self.samples):
            # Split into training and testing sets
            TRAIN_GOODWARE,TRAIN_MALWARE,TEST = self.defineClassification(train_index,test_index)
            self.train(TRAIN_GOODWARE,TRAIN_MALWARE)
            self.test(TEST)
            self.determineMetrics(TEST)
        self.determineAverageMetrics()
        self.printData()
        self.clearMetrics()
        return

    def trainingTesting(self,goodware,malware,suspicious):
        self.train(goodware,malware)
        self.test(suspicious)
        self.determineMetrics(suspicious)
        self.determineAverageMetrics()
        self.printData()
        return


    # Determines the percentage error in each iteration and # of false
    # positives/negatives
    def determineMetrics(self,suspicious):
        split_metrics = dm.DataMetrics()

        for binary in suspicious:
            # Labels do not match
            if(not(self.labelsMatch(binary))):
                # False positive/negative
                if(binary.getOriginalLabel() == 'goodware'):
                    split_metrics.incrementFn()
                else:
                    split_metrics.incrementFp()
            # labelsMatch
            else:
                if(binary.getOriginalLabel() == 'goodware'):
                    split_metrics.incrementTp()
                else:
                    split_metrics.incrementTn()

        split_metrics.calculateAll()
        self.it_metrics.append(split_metrics)
        return


    def clearMetrics(self):
        self.it_metrics = []
        self.avrg_metrics = None
        return

    def determineAverageMetrics(self):
        self.avrg_metrics = dm.DataMetrics()

        for split_metric in self.it_metrics:
            self.avrg_metrics.incrementFp(split_metric.getFp())
            self.avrg_metrics.incrementFn(split_metric.getFn())
            self.avrg_metrics.incrementTp(split_metric.getTp())
            self.avrg_metrics.incrementTn(split_metric.getTn())

        self.avrg_metrics.calculateAll()
        return


    #Compare label and discovered label
    def labelsMatch(self,binary):
        if(binary.getDeterminedLabel() == 'unset'):
            print('ERROR: \{ML.PY\} Unset label by ml algorithm.')
            exit(0)
        if(binary.getOriginalLabel() != binary.getDeterminedLabel()):
            return False # Labels are different
        else:
            return True  # Labels match


    # Separates the training and testing index of KFold into goodware, malware
    # and test list
    def defineClassification(self,train_index,test_index):
        TRAIN_GOODWARE = []
        TRAIN_MALWARE = []
        TEST =[]

        for index in train_index:
            if self.samples[index].getOriginalLabel() == "goodware":
                TRAIN_GOODWARE.append(self.samples[index])
            if self.samples[index].getOriginalLabel() == "malware":
                TRAIN_MALWARE.append(self.samples[index])

        for index in test_index:
            TEST.append(self.samples[index])

        return TRAIN_GOODWARE,TRAIN_MALWARE,TEST


    def test(self,suspicious):
        config = ConfigParser.RawConfigParser()
        config.read('forsite.conf')

        if(config.get('Classifier','Analysis') == 'Static'):
            if(config.get('Classifier','Features') == 'Discrete'):
                for binary in suspicious:
                    binary.setDeterminedLabel(self.predict(binary.getDiscreteList()))
            elif(config.get('Classifier','Features') == 'Continuous'):
                for binary in suspicious:
                    binary.setDeterminedLabel(self.predict(binary.getContinuousList()))
            else:
                pass
        elif(config.get('Classifier','Analysis') == 'Dynamic'):
            if(config.get('Classifier','Features') == 'Discrete'):
                for binary in suspicious:
                    binary.setDeterminedLabel(self.predict(binary.getDynamicDiscreteList()))
            elif(config.get('Classifier','Features') == 'Continuous'):
                for binary in suspicious:
                    binary.setDeterminedLabel(self.predict(binary.getDynamicContinuousList()))
            else:
                pass
        return


    def predict(self,features):
        # Internal method for single binary prediction
        return self.clf.predict([features])[0]


    def featureAndLabels(self,goodware,malware):
        feature_list = []
        label_list   = []
        # Appends binaries into different list, one for features and another for labels
        # Opens config file with user configurations
        config = ConfigParser.RawConfigParser()
        config.read('forsite.conf')
        if(config.get('Classifier','Analysis') == 'Static'):
            if(config.get('Classifier','Features') == 'Discrete'):
                for binary in (goodware + malware):
                    feature_list.append(binary.getDiscreteList())
                    label_list.append(binary.getOriginalLabel())
            elif(config.get('Classifier','Features') == 'Continuous'):
                for binary in (goodware + malware):
                    feature_list.append(binary.getContinuousList())
                    label_list.append(binary.getOriginalLabel())
            else:
                print('ERROR \{ML.PY\} Feature and Labels. Feature not set.')
                exit(0)
        elif(config.get('Classifier','Analysis') == 'Dynamic'):
            if(config.get('Classifier','Features') == 'Discrete'):
                for binary in (goodware + malware):
                    feature_list.append(binary.getDynamicDiscreteList())
                    label_list.append(binary.getOriginalLabel())
            elif(config.get('Classifier','Features') == 'Continuous'):
                for binary in (goodware + malware):
                    feature_list.append(binary.getDynamicContinuousList())
                    label_list.append(binary.getOriginalLabel())
            else:
                print('ERROR \{ML.PY\} Feature and Labels. Feature not set.')
                exit(0)
        else:
            print('ERROR \{ML.PY\} Dynamic and Static. Feature not set.')
            exit(0)

        return feature_list,label_list


    # Prints formated error data generated by KFold testing
    def printData(self):
        print('************************************************************')
        print self.clf
        print('************************************************************')
        print('{:^12}{:^12}{:^12}{:^12}{:^12}{:^12}{:^12}{:^12}{:^12}'.format('Iteration',
                                      'Accuracy',
                                      'Precision',
                                      'Recall',
                                      'F1',
                                      'TP',
                                      'TN',
                                      'FP',
                                      'FN'))
        print('************************************************************')
        for c,item in enumerate(self.it_metrics,1):
            print('{:^12}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}'.format(
                                              c,item.getAccuracy(),
                                                item.getPrecision(),
                                                item.getRecall(),
                                                item.getF1(),
                                                item.getTp(),
                                                item.getTn(),
                                                item.getFp(),
                                                item.getFn()))
        print('************************************************************')
        print('{:^12}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}{:^12.4}'.format('Average',
                                                self.avrg_metrics.getAccuracy(),
                                                self.avrg_metrics.getPrecision(),
                                                self.avrg_metrics.getRecall(),
                                                self.avrg_metrics.getF1(),
                                                self.avrg_metrics.getTp(),
                                                self.avrg_metrics.getTn(),
                                                self.avrg_metrics.getFp(),
                                                self.avrg_metrics.getFn()))
        print('************************************************************')
        # for binary in self.v_list:
        #     print(os.path.basename(binary.getElf()))
        #     print('Original: '+binary.getLabel()+'   Discovered: '+binary.getDLabel())
        #     print('{:^40}'.format('*******'))
        return

# Machine learning class for random forest algorithm
class RandomForest(MachineLearing):
    def __init__(self,samples):
        MachineLearing.__init__(self,samples)
        self.n_estimators = 10   # Default value
        self.max_depth = None
        self.max_leaf_nodes = None

    def multipleRun(self):
        i = 8
        while i <= 128:
            self.n_estimators = i
            j = 4
            while j <= 64:
                self.max_depth = j
                self.singleRun()
                j = j*2
            i = i*2
            # self.clearMachineLearning()
        return

    # Train the classifier
    def train(self,goodware,malware):
        feature_list = []
        label_list   = []
        feature_list,label_list = self.featureAndLabels(goodware,malware)

        # Calls random forest algorithm with determined number of estimators
        self.clf = RandomForestClassifier(n_estimators = self.n_estimators,max_depth=self.max_depth,max_leaf_nodes=self.max_leaf_nodes )
        self.clf.fit(feature_list,label_list)
        return


# Class for Svm machine learning algorithm
class Svm(MachineLearing):
    def __init__(self,samples):
        MachineLearing.__init__(self,samples)
        self.max_iter = 1000
        self.decision_function_shape = 'ovr'
        self.kernel = 'linear'

    def multipleRun(self):
        kernels = ['poly','rbf','linear']
        i = 1000
        while i <= 100000:
            self.max_iter = i
            for k in kernels:
                self.kernel = k
                self.singleRun()
            i = i*10

        # self.clearMachineLearning()
        return

    def train(self,goodware,malware):
        feature_list = []
        label_list   = []
        feature_list,label_list = self.featureAndLabels(goodware,malware)
        if(self.kernel == 'linear'):
            self.clf = svm.LinearSVC(max_iter=self.max_iter)
        else:
            self.clf = svm.SVC(max_iter=self.max_iter,kernel=self.kernel,gamma='auto')
        self.clf.fit(feature_list, label_list)

        return

class MLP(MachineLearing):
    def __init__(self,samples):
        MachineLearing.__init__(self,samples)
        self.alpha = 0.1
        self.solver = 'adam'

    def multipleRun(self):
        solvers = ['adam','lbfgs','sgd']
        i = 0.01
        while i <= 1000:
            self.alpha = i
            for k in solvers:
                self.solver = k
                self.singleRun()
            i = i*10
            # self.clearMachineLearning()
        return

    def train(self,goodware,malware):
        feature_list = []
        label_list   = []
        feature_list,label_list = self.featureAndLabels(goodware,malware)

        self.clf = MLPClassifier(solver=self.solver, alpha=self.alpha,
                                 hidden_layer_sizes=(10,10), random_state=1)
        self.clf.fit(feature_list, label_list)
        return






 # Project Forseti/Forsight
# # Machine Learning System
#
# from sklearn import svm # Machine Learning algorithm
# from sklearn.model_selection import KFold # KFold algorithm
# import binaries         # Object class for handling binaries
# import ConfigParser     # Configuration file for user
# import pickle
# import sys
#
# # Parent class for different machine learning algorithms
# class MachineLearing:
#
#     def train(self,goodware,malware):
#         pass
#
#     def test(self,suspicious):
#         pass
#
#     def pickleDump():
#         pass
#
#     def pickleLoad():
#         pass
#
# # Class for Svm machine learning algorithm
# class Svm(MachineLearing):
#     def __init__(self):
#         self.samples = []
#         self.labels = []
#         self.clf  = None
#
#     def train(self,goodware,malware):
#         # Trains for goodware and malware
#         for binary in (goodware + malware):
#             self.samples.append(binary.flist)
#             self.labels.append(binary.label)
#         self.clf = svm.SVC()
#         self.clf.fit(self.samples, self.labels)
#         # Pickle clf
#         self.pickleDump()
#         return
#
#     def predict(self,binary):
#         # Internal method for single binary prediction
#         return self.clf.predict([binary.flist])[0]
#
#     def test(self,suspicious):
#         # Unpickle clf
#         self.pickleLoad()
#         # Uses internal method to predict suspicious binaries
#         for binary in suspicious:
#             binary.d_label =  self.predict(binary)
#         return suspicious
#
#     def pickleDump(self):
#         # Open user configuration file
#         config = ConfigParser.RawConfigParser()
#         config.read('forsite.conf')
#         try:
#             # Data will be pickled to file
#             pickle_out = open(config.get('ml','Fit'),"wb")
#             pickle.dump(self.clf,pickle_out)
#             pickle_out.close()
#         except:
#             print("Invalid pickle machine learning file for dump in forsite.conf.\n")
#
#         return
#
#     def pickleLoad(self):
#         if(self.clf != None):
#             # Algorithm has just been trained and does not require to be unpickled
#             return
#         # Open user configuration file
#         config = ConfigParser.RawConfigParser()
#         config.read('forsite.conf')
#         try:
#             # Data will be unpickled from file
#             pickle_in = open(config.get('ml','Fit'),"rb")
#             self.clf = pickle.load(pickle_in)
#             pickle_in.close()
#         except:
#             print("Invalid pickle machine learning file for load in forsite.conf.\n")
#
#         return
#
#
# #Class for machine learning KFold error cross validation testing
# class CrossValidationKFold:
#
#     def __init__(self,n_splits,validation_list):
#         # Number of splits to be done by kfold algorithm
#         self.n_splits = n_splits
#         # List with all samples to be validated by kfold. (This is the train list of goodware and malware.)
#         self.v_list = validation_list
#         # Validation error dictionary. False positive/negatives and percentage.
#         self.error = {
#                         "fp" : 0,        # False positive #
#                         "fn" : 0,        # False negative #
#                         "p_error" : [],  # Error in each split %
#                         "f_error" : 0.0  # Final average error
#         }
#
#     # Generates the KFold object from sklearn, with n_split, shuffle
#     # enabled so goodware and malware are spread out and random_state
#     # set to 1 for debugging purposes.
#     def executeKFold(self):
#         kf = KFold(n_splits=self.n_splits,shuffle=True,random_state=1)
#
#         # Split into training and testing sets
#         for train_index,test_index in kf.split(self.v_list):
#             goodware,malware,suspicious = self.separateList(train_index,test_index)
#             self.runML(goodware,malware,suspicious)
#             self.determineError(suspicious)
#
#         self.determineFinalError()
#         self.printError()
#         return
#
#
#     # Separates the training and testing index of KFold into goodware, malware
#     # and suspicious list form ml testing.
#     def separateList(self,train,test):
#         goodware = []
#         malware = []
#         suspicious =[]
#
#         for index in train:
#             if self.v_list[index].label == "goodware":
#                 goodware.append(self.v_list[index])
#             if self.v_list[index].label == "malware":
#                 malware.append(self.v_list[index])
#
#         for index in test:
#             suspicious.append(self.v_list[index])
#
#         return goodware,malware,suspicious
#
#     # Will run the ml code for training and testing of the the
#     # KFold cross validation
#     def runML(self,goodware,malware,suspicious):
#         ml = Svm()
#         ml.train(goodware,malware)
#         ml.test(suspicious)
#         return
#
#     # Determines the percentage error in each iteration and # of false
#     # positives/negatives
#     def determineError(self,suspicious):
#         errorCountTemp = 0.0    #  Temporary counter of error
#         for binary in suspicious:
#             if(self.compareLabels(binary)):
#                 errorCountTemp += 1
#                 if(binary.getLabel() == 'goodware'):
#                     self.error["fp"] += 1 # False positive
#                 else:
#                     self.error["fn"] += 1 # False negative
#         # Percentage error 1 - fails/suspicious
#         self.error["p_error"].append(1.0 - errorCountTemp/len(suspicious))
#         return
#
#     def determineFinalError(self):
#         self.error["f_error"] = sum(self.error["p_error"])/len(self.error["p_error"])
#         return
#
#     #Compare label and discovered label
#     def compareLabels(self,binary):
#         if(binary.d_label == 'unset'):
#             print('Unset label error.\n')
#             exit(0)
#         if(binary.label != binary.d_label):
#             return True # Labels are different
#         return False    # Labels match
#
#     # Prints formated error data generated by KFold testing
#     def printError(self):
#         print('*********************************************')
#         print('*********************************************')
#         print('{}{:^50}'.format('Iteration','Correctness'))
#         print('*********************************************')
#         for c,item in enumerate(self.error["p_error"],1):
#             print('{}{:^60}'.format(c,item))
#         print('*********************************************')
#         print('# False Positives: ',self.error['fp'])
#         print('# False Negatives: ',self.error['fn'])
#         print('Average Correctness: ',self.error['f_error'])
#         print('*********************************************')
#         return
