# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

class DataMetrics:
    def __init__(self):
        self.fp = 0.0          # False postive
        self.fn = 0.0          # False negative
        self.tp = 0.0          # True positive
        self.tn = 0.0          # True negative
        self.accuracy = None    # Accuracy
        self.precision = None   # Precision
        self.recall = None      # Recall
        self.f1 = None          # F1

    def incrementFp(self,amount=1.0):
        self.fp += amount

    def incrementFn(self,amount=1.0):
        self.fn += amount

    def incrementTp(self,amount=1.0):
        self.tp += amount

    def incrementTn(self,amount=1.0):
        self.tn += amount

    def getFp(self):
        return self.fp

    def getFn(self):
        return self.fn

    def getTp(self):
        return self.tp

    def getTn(self):
        return self.tn

    def getAccuracy(self):
        return self.accuracy

    def getPrecision(self):
        return self.precision

    def getRecall(self):
        return self.recall

    def getF1(self):
        return self.f1

    def calculateAccuracy(self):
        # =(tp + tn)/(tp + tn + fp + fn)
        try:
            self.accuracy = (self.getTp() + self.getTn())/(self.getTp() + self.getTn() + self.getFp() + self.getFn())
        except:
            # print('Error DM: Accuracy calculation.')
            pass
        return

    def calculatePrecision(self):
        # =(tp)/(tp + fp)
        try:
            self.precision = (self.getTp())/(self.getTp() + self.getFp())
        except:
            # print('Error DM: Precision calculation.')
            pass
        return

    def calculateRecall(self):
        # =(tp)/(tp + fn)
        try:
            self.recall = (self.getTp())/(self.getTp() + self.getFn())
        except:
            # print('Error DM: Recall calculation.')
            pass
        return

    def calculateF1(self):
        # =2*(precision*recall)/(precision+recall)
        try:
            self.f1 = 2*(self.getPrecision()*self.getRecall())/(self.getPrecision()+self.getRecall())
        except:
            # print('Error DM: F1 calculation.')
            pass
        return

    def calculateAll(self):
        self.calculateAccuracy()
        self.calculatePrecision()
        self.calculateRecall()
        self.calculateF1()
        return
