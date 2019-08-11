# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

import binaries            # Object class for storing and manipulating binaries
import subprocess as sp    # PIPE for terminal commands
import os
import net

# Pyelftools
# Parse and analyze ELF files for debugging information
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

class Static():
    def getElffile(self,binary):
        # Operates ELFFile on the open binary and saves due to multiple access
        # ELFFile is a method defined by pyelftools
        if(binary.getElfFile() == None):
            try:
                f =  open(binary.getElf(), 'rb')
                binary.setElfFile(ELFFile(f))
                # f.close() CANNOT CLOSE FILE WHILE COLLECTING INFO
            except:
                binary.setElfFile(None)
        return

    def runStrings(self,binary):
        #If strings has run before, no need to run again
        if(binary.getStrings() != None):
            return
        #Run strings on the binary
        p = sp.Popen("strings " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #out is output of file command
        out, err = p.communicate()
        #Save output of strings in the binary object
        binary.setStrings(out)
        return

class StaticDiscrete(Static):
    def runAll(self,binary):
        self.runForemost(binary)
        self.NetStrings(binary)
        self.HeaderPresent(binary)
        self.Linkage(binary)
        self.UpxPresent(binary)
        self.ForkPresent(binary)
        self.ObjdumpFail(binary)
        self.PtracePresent(binary)
        self.checkHome(binary)
        self.checkSys(binary)
        self.checkPassw(binary)
        self.CompilerStrings(binary)

    def runObjdumpT(self,binary):
        #If objdump -T has run before, no need to run again
        if(binary.getObjdumpT() != None):
            return
        #Run objdump T for dynamic symbol table info
        p = sp.Popen("objdump -T " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #out is output of file command
        out, err = p.communicate()
        #Save output of objdump -T in the binary object
        binary.setObjdumpT(out)
        return



    def runForemost(self,binary):
        #Check for static or dynamic linkage
        p = sp.Popen("foremost -t all -i " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #out is output of file command
        out, err = p.communicate()
        try:
            audit = open("./output/audit.txt")
            for line in audit:
                if "0 FILES EXTRACTED" in line:
                    # No embedded file
                    binary.appendDiscreteList(0)
                    return
            #At least 1 embedded file
            binary.appendDiscreteList(1)
            audit.close()
        except:
            print("FAILED!")
        p = sp.Popen("rm -rf output",stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        return


    def NetStrings(self,binary):
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendDiscreteList(0)
            return
        npy = net.Net()
        url,ip,mail = npy.check_strings(binary.getStrings())

        binary.appendDiscreteList(1 if (url > 0) else 0)
        binary.appendDiscreteList(1 if (ip > 0) else 0)
        binary.appendDiscreteList(1 if (mail > 0) else 0)

    def HeaderPresent(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendDiscreteList(0)
            return
        # Returns number of sections present in the binary
        binary.appendDiscreteList(1 if (binary.getElfFile().header['e_phnum'] > 0) else 0)
        return


    def Linkage(self,binary):
        #Check for static or dynamic linkage
        try:
            p = sp.Popen("file " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
            #out is output of file command
            out, err = p.communicate()
            if("statically linked" in out):
                binary.appendDiscreteList(1)
                return #Presents static linkage feature
            else:# ("dynamically linked" in out):
                binary.appendDiscreteList(0)
                return #Does not present static linkage feature
        except:
            binary.appendDiscreteList(0)
            return
        # else:
        #     print("NOT HANDLED: static.py Linkage()")
        #     return -1


    def UpxPresent(self,binary):
        #Perform upx -l to check for UPX package
        p = sp.Popen("upx -l " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #err will contain error message in case file not packed
        out, err = p.communicate()

        if("not packed by UPX" in err): #Not packed
            binary.appendDiscreteList(0)
        else:                           #Packed by UPX!
            binary.appendDiscreteList(1)
        return

    def ForkPresent(self,binary):
        #Call for objdump -T for the binary
        self.runObjdumpT(binary)
        #Check if fork is present in dynamic symbol table
        if("fork" in binary.getObjdumpT()):
            binary.appendDiscreteList(1)
            return     #fork present
        else:
            binary.appendDiscreteList(0)
            return     #not present

    def ObjdumpFail(self,binary):
        #Call for objdump -T for the binary
        self.runObjdumpT(binary)
        #Check if objdump -T failed or not by checking dynamic symbol table
        if("no symbols" in binary.getObjdumpT()):
            binary.appendDiscreteList(1)
            return     #objdump fail
        else:
            binary.appendDiscreteList(0)
            return     #works

    def PtracePresent(self,binary):
        #Call for objdump -T for the binary
        self.runObjdumpT(binary)
        #Check if ptrace is present in dynamic symbol table
        if("ptrace" in binary.getObjdumpT()):
            binary.appendDiscreteList(1)
            return     #ptrace present
        else:
            binary.appendDiscreteList(0)
            return     #not present

    def checkHome(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendDiscreteList(0)
            return
        #Check if /home or /var is present in dynamic symbol table
        if("/var" in binary.getStrings() or "/home" in binary.getStrings()):
            binary.appendDiscreteList(1)
            return     #directories present
        else:
            binary.appendDiscreteList(0)
            return     #not present

    def checkSys(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendDiscreteList(0)
            return
        #Check if /proc or /sys is present in dynamic symbol table
        if("/proc" in binary.getStrings() or "/sys" in binary.getStrings()):
            binary.appendDiscreteList(1)
            return     #directories present
        else:
            binary.appendDiscreteList(0)
            return     #not present

    def checkPassw(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendDiscreteList(0)
            return
        #Check if passwd or shadow is present in dynamic symbol table
        if("passwd" in binary.getStrings() or "shadow" in binary.getStrings()):
            binary.appendDiscreteList(1)
            return     #directories present
        else:
            binary.appendDiscreteList(0)
            return     #not present

    def CompilerStrings(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendDiscreteList(0)
            return
        #Check how many compilers symbols there are
        counter = 0
        for line in binary.getStrings():
            if('gcc' in line or 'GCC' in line):
                counter += 1

        if(counter > 1):
            binary.appendDiscreteList(1)
        else:
            binary.appendDiscreteList(0)
        return


class StaticContinuous(Static):
    def runAll(self,binary):
        self.sizeSections(binary)
        self.checkHome(binary)
        self.checkSys(binary)
        self.checkPassw(binary)
        self.numLibs(binary)
        self.sizeBinary(binary)
        self.numHeaders(binary)
        self.dynSymbols(binary)
        self.numSections(binary)
        self.numSymbols(binary)
        self.numRelocations(binary)
        self.numDebugSection(binary)

    def checkHome(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendContinuousList(0)
            return
        try:
            num_dir = binary.getStrings().count('/home')
            num_dir += binary.getStrings().count('/var')
            binary.appendContinuousList(num_dir)
        except:
            binary.appendContinuousList(0)

    def checkSys(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendContinuousList(0)
            return
        try:
            num_dir = binary.getStrings().count('/proc')
            num_dir += binary.getStrings().count('/sys')
            binary.appendContinuousList(num_dir)
        except:
            binary.appendContinuousList(0)

    def checkPassw(self,binary):
        #Call for strings of the binary
        self.runStrings(binary)
        if(binary.getStrings() == None):
            #Default is 0
            binary.appendContinuousList(0)
            return
        try:
            num_dir = binary.getStrings().count('passwd')
            num_dir += binary.getStrings().count('shadow')
            binary.appendContinuousList(num_dir)
        except:
            binary.appendContinuousList(0)

    def numLibs(self,binary):
        #Perform du -k to get size of binary
        p = sp.Popen("ldd " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #err will contain error message in case file not packed
        out, err = p.communicate()

        try:
            if('not a dynamic executable' in out):
                binary.appendContinuousList(0)
            else:
                num_lines = 0
                for letter in out:
                    if (letter == '\n'):
                        num_lines += 1
                binary.appendContinuousList(num_lines)
        except:
            binary.appendContinuousList(0)
        return

    def sizeSections(self,binary):
        #Perform du -k to get size of binary
        p = sp.Popen("readelf --sections " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #err will contain error message in case file not packed
        out, err = p.communicate()
        doc = []
        line = []
        for letter in out:
            if (letter == '\n'):
                line = ''.join(line)
                doc.append(line)
                line = []
            else:
                line.append(letter)
        self.checkSymbolSize(binary,'.text',doc)
        self.checkSymbolSize(binary,'.data',doc)
        self.checkSymbolSize(binary,'.interp',doc)

    def checkSymbolSize(self,binary,symbol,doc):
        try:
            for c,line in enumerate(doc,0):
                if(symbol in line):
                    binary.appendContinuousList(int(doc[c+1].split()[0],16))
                    return
            binary.appendContinuousList(0)
        except:
            binary.appendContinuousList(0)
        return


    def sizeBinary(self,binary):
        #Perform du -k to get size of binary
        p = sp.Popen("du -k " + binary.getElf(),stdout=sp.PIPE,stderr=sp.PIPE,shell=True)
        #err will contain error message in case file not packed
        out, err = p.communicate()

        try:
            size = int(out.split('\t')[0])
            binary.appendContinuousList(size)
        except:
            binary.appendContinuousList(0)
        return


    def numHeaders(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendContinuousList(0)
            return
        # Returns number of sections present in the binary
        binary.appendContinuousList(binary.getElfFile().header['e_phnum'])
        return


    def numSections(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendContinuousList(0)
            return
        # Returns number of sections present in the binary
        binary.appendContinuousList(binary.getElfFile().num_sections())
        return

    def dynSymbols(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendContinuousList(0)
            return
        try:
            # Note that section names are strings.
            section = binary.getElfFile().get_section_by_name('.dynamic')
            try:
                binary.appendContinuousList(section.num_tags())
            except:
                binary.appendContinuousList(0)
        except:
            binary.appendContinuousList(0)


    def numSymbols(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendContinuousList(0)
            return
        # Note that section names are strings.
        section = binary.getElfFile().get_section_by_name('.symtab')

        if not section:
            #No symbol table found. Perhaps this ELF has been stripped?
            binary.appendContinuousList(0)
            return 0

        #Returns the number of symbols present in SYMBOL TABLE
        if isinstance(section, SymbolTableSection):
            binary.appendContinuousList(section.num_symbols())
            return

    def numRelocations(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendContinuousList(0)
            return
        reladyn_name = '.rela.dyn'
        reladyn = binary.getElfFile().get_section_by_name(reladyn_name)

        if not isinstance(reladyn, RelocationSection):
            #  The file has no relocation section
            binary.appendContinuousList(0)
            return 0

        # Returns the number of relocations in the binary
        binary.appendContinuousList(reladyn.num_relocations())

    def numDebugSection(self,binary):
        self.getElffile(binary)
        if(binary.getElfFile() == None):
            binary.appendContinuousList(0)
            return
        # Counts and returns the number of debug sections in the binary
        try:
            counter = 0
            for section in binary.getElfFile().iter_sections():
                if section.name.startswith('.debug'):
                    counter += 1
            binary.appendContinuousList(counter)
        except:
            binary.appendContinuousList(0)
