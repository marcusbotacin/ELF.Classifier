# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

from sklearn.model_selection import KFold

omega = ['a','b','c','d','e']

kf1 = KFold(n_splits=2,shuffle=True,random_state=1)

tr,ts = kf1.split(omega)

print tr[0]

for i in tr:
    for j in i:
        print j


# for train_index, test_index in kf1.split(omega):
#     print(train_index,test_index)
