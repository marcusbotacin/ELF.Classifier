# Forseti

Forseti is a prototype for binary classification (malware/goodware) targeting ELF/Linux binaries.

## Authors

Forseti was authored by Lucas Galante under supervision of Marcus Botacin, André Grégio and Paulo de Geus.

## Motivation

Forseti is inspired by the lack of didactic, academic tools for exploring Linux binaries.

## Repository Organization

The repository is organized as follows:

* **code**: Contains Forseti's Python scripts.
* **data**: Contains Forseti's configuration files, databases and configuration files' samples.
* **paper**: Contains a copy of our white-paper.
* **tests**: Contains Forseti's test-case files.

## Papers

Forseti is supported by a series of developments and described in multiple papers:

* Forseti feature extraction mechanisms are described in the course *Introdução à Engenharia Reversa de Aplicações Maliciosas em Ambientes Linux*, published in the *XIX SBSEG*. [Check Here](https://github.com/marcusbotacin/Malware.Reverse.Intro/blob/master/SBSEG/curso.pdf)
* Forseti feature extraction capabilities were used to describe the landscape of Linux malware presented in the paper *Malicious Linux Binaries: A Landscape*, published in the *XVIII SBSEG* [Check Here](https://github.com/marcusbotacin/Linux.Malware/blob/master/paper.pdf)
* Forseti classification capabilities are described in the paper *Forseti: Extração de características e classificação de binários ELF*, published in the *XIX SBSEG* [Check Here](paper/forseti.pdf)
* Forseti evaluation was presented in the paper *Machine Learning for Malware Detection: Beyond Accuracy Rates*, published in the *XIX SBSEG* [Check Here](paper/classifier.pdf)

## Installation

Install the following dependencies to run Forseti:

```C
pip install pyelftools
pip install pickle
pip install configparser
pip install sklearn
```

## Execution

Forseti can be trained by providing it with a list of goodware and malware files:

```C
python main.py -g goodware.txt -m malware.txt
```

The list should look like:
```C
$> cat data/malware.txt 
> tests/static_malicious.bin
> tests/upx.bin
> tests/fork.bin
```

Alternatively, one can also provide a list of suspicious files to be classified:

```C
python main.py -g goodware.txt -m malware.txt -s suspicious.txt
```

Or, automate everything using our script:
```C
./run-forsite.sh
```

## Forseti Internals

If you want to take a look on how Forseti extracts features, you might want to look:

* **static.py**: Static feature extraction.
* **dynamic.py**: Dynamic feature extraction.

If you want to take a look on Forseti training, you might want to look:

* **kfold.py**: Folding training implementation.
* **ml.py**: Classifiers implementation.

More specifically, you might want to change the implemented classifiers by implementing a new class that inherits the *MachineLearning* class, as Forseti does to implement its classifiers. The currently implemented classifiers are:

```C
class RandomForest(MachineLearing)
class Svm(MachineLearing)
class MLP(MachineLearing)
```
