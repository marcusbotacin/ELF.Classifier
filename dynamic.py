# FORSETI - Feature extractor and classificator for ELF binaries
# Author: Lucas Galante
# Advisor: Marcus Botacin, Andre Gregio, Paulo de Geus
# 2019, UFPR, UNICAMP

import binaries            # Object class for storing and manipulating binaries
import subprocess as sp    # PIPE for terminal commands
import os
import net

class Dynamic():#Dynamic):
    def runAll(self,binary):
        f = open(binary.getElf())
        self.parse_lines(binary,f)
        f.close()
        return

    def parse_lines(self,binary,f):
        fork_count = 0
        ptrace_count = 0
        socket_count = 0
        mmap_count = 0
        term_count = 0
        segv_count = 0
        proc_count = 0
        home_count = 0
        passwd_count = 0
        denied_count = 0
        f.seek(0)
        for i in f:
            fork_count += i.count("clone")
            fork_count += i.count("fork")
            ptrace_count += i.count("ptrace")
            socket_count += i.count("socket")
            mmap_count += i.count("mmap")
            term_count += i.count("SIGTERM")
            term_count += i.count("SIGKILL")
            segv_count += i.count("SIGSEGV")
            proc_count += i.count("/proc")
            proc_count += i.count("/sys")
            home_count += i.count("/home")
            home_count += i.count("/var")
            passwd_count += i.count("passwd")
            passwd_count += i.count("shadow")
            denied_count += i.count("denied")
        # Continuous
        binary.appendDynamicContinuousList(fork_count)
        binary.appendDynamicContinuousList(ptrace_count)
        binary.appendDynamicContinuousList(socket_count)
        binary.appendDynamicContinuousList(mmap_count)
        binary.appendDynamicContinuousList(term_count)
        binary.appendDynamicContinuousList(segv_count)
        binary.appendDynamicContinuousList(proc_count)
        binary.appendDynamicContinuousList(home_count)
        binary.appendDynamicContinuousList(passwd_count)
        binary.appendDynamicContinuousList(denied_count)
        # Discrete
        binary.appendDynamicDiscreteList(1 if (fork_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (ptrace_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (socket_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (mmap_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (term_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (segv_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (proc_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (home_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (passwd_count > 0) else 0)
        binary.appendDynamicDiscreteList(1 if (denied_count > 0) else 0)

        return
