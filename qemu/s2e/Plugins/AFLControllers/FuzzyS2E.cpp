/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2015, Information Security Laboratory, NUDT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Information Security Laboratory, NUDT nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE INFORMATION SECURITY LABORATORY, NUDT BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

#include "FuzzyS2E.h"
extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include <sysemu.h>
#include <sys/shm.h>
}
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Opcodes.h>
#include <s2e/Utils.h>

#include <iomanip>
#include <cctype>

#include <algorithm>
#include <fstream>
#include <vector>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>    /**/
#include <errno.h>     /*errno*/
#include <unistd.h>    /*ssize_t*/
#include <sys/types.h>
#include <sys/stat.h>  /*mode_t*/
#include <stdlib.h>

extern int errno;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FuzzyS2E, "FuzzyS2E plugin", "FuzzyS2E",
        "ModuleExecutionDetector", "HostFiles", "KernelFunctionMonitor");

FuzzyS2E::~FuzzyS2E()
{
}
void FuzzyS2E::initialize()
{
    bool ok = false;
    std::string cfgkey = getConfigKey();
    m_HostFiles = (HostFiles*)s2e()->getPlugin("HostFiles");
    m_verbose = s2e()->getConfig()->getBool(getConfigKey() + ".debugVerbose",
            false, &ok);

    m_mainModule = s2e()->getConfig()->getString(cfgkey + ".mainModule",
            "MainModule", &ok);
    m_afl_initDir = s2e()->getConfig()->getString(cfgkey + ".aflInitDir",
            "INIT", &ok);
    m_detector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin(
            "ModuleExecutionDetector"));
    if (!m_detector) {
        std::cerr << "Could not find ModuleExecutionDetector plug-in. " << '\n';
        exit(0);
    }
    m_detector->onModuleTranslateBlockStart.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onModuleTranslateBlockStart));


    m_kfmonitor = static_cast<KernelFunctionMonitor*>(s2e()->getPlugin(
            "KernelFunctionMonitor"));
    if (!m_kfmonitor) {
        std::cerr << "Could not find KernelFunctionMonitor plug-in. " << '\n';
        exit(0);
    }
    m_kfmonitor->onKernelFunctionExecutionStart.connect(sigc::mem_fun(*this, &FuzzyS2E::onKernelFunctionExecutionStart));


    m_detector->onModuleTranslateBlockStart.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onModuleTranslateBlockStart));
    s2e()->getCorePlugin()->onCustomInstruction.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onCustomInstruction));
    m_QEMUPid = getpid();
    m_PPid = getppid();
    if (!m_findBitMapSHM)
        m_findBitMapSHM = getAFLBitmapSHM();
    assert(m_aflBitmapSHM && "AFL's trace bits bitmap is NULL, why??");
    if(!initReadySHM())
        exit(EXIT_FAILURE);
    if(!initQemuQueue())
        exit(EXIT_FAILURE);
    std::stringstream testcase_strstream;
    testcase_strstream << "/tmp/afltestcase/" << m_QEMUPid;
    if (::access(testcase_strstream.str().c_str(), F_OK)) // for all testcases
        mkdir(testcase_strstream.str().c_str(), 0777);
    if(!m_HostFiles->addDirectories(testcase_strstream.str()))
        exit(EXIT_FAILURE);

    s2e()->getExecutor()->setSearcher(this);
}

//return *states[theRNG.getInt32()%states.size()];

klee::ExecutionState& FuzzyS2E::selectState()
{
    klee::ExecutionState *state;
    if (!m_speculativeStates.empty()) { //to maximum random, priority to speculative state
        States::iterator it = m_speculativeStates.begin();
        int random_index = rand() % m_speculativeStates.size(); //random select a testcase
        while (random_index) {
            it++;
            random_index--;
        }
        state = *it;
    } else {
        assert(!m_normalStates.empty());
        if(m_normalStates.size() == 1){ // we have only one state, it MUST be the initial state
            States::iterator it = m_normalStates.begin();
            return *(*it);
        }
        // if not, we randomly select a normal state.
        States::iterator it = m_normalStates.begin();
        int random_index = rand() % (m_normalStates.size() - 1);
        it++; // move to second
        while (random_index) {
            it++;
            random_index--;
        }
        state = *it;
    }
    return *state;
}

void FuzzyS2E::update(klee::ExecutionState *current,
        const std::set<klee::ExecutionState*> &addedStates,
        const std::set<klee::ExecutionState*> &removedStates)
{
    if (current && addedStates.empty() && removedStates.empty()) {
        S2EExecutionState *s2estate = dynamic_cast<S2EExecutionState*>(current);
        if (!s2estate->isZombie()) {
            if (current->isSpeculative()) {
                m_normalStates.erase(current);
                m_speculativeStates.insert(current);
            } else {
                m_speculativeStates.erase(current);
                m_normalStates.insert(current);
            }
        }
    }

    foreach2(it, removedStates.begin(), removedStates.end())
    {
        if (*it == NULL)
            continue;
        S2EExecutionState *es = dynamic_cast<S2EExecutionState*>(*it);
        if (es->isSpeculative()) {
            m_speculativeStates.erase(es);
        } else {
            m_normalStates.erase(es);
        }
    }

    foreach2(it, addedStates.begin(), addedStates.end())
    {
        if (*it == NULL)
            continue;
        S2EExecutionState *es = dynamic_cast<S2EExecutionState*>(*it);
        if (es->isSpeculative()) {
            m_speculativeStates.insert(es);
        } else {
            m_normalStates.insert(es);
        }
    }

}

bool FuzzyS2E::empty()
{
    return m_normalStates.empty() && m_speculativeStates.empty();
}


void FuzzyS2E::onModuleTranslateBlockStart(ExecutionSignal* es,
        S2EExecutionState* state, const ModuleDescriptor &mod,
        TranslationBlock* tb, uint64_t pc)
{
    if (!tb) {
        return;
    }
    if(!m_mainPid)
        m_mainPid = state->getPid(); // get pid at first time and only do it once
    if (m_mainModule == mod.Name) {
        es->connect(
        sigc::mem_fun(*this, &FuzzyS2E::slotExecuteBlockStart));
    }

}

/**
 */
void FuzzyS2E::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    if (!state->getID())
        return;
    if (pc > 0xc000000) // Ignore kernel module in order to compare with vanilla AFL
        return;
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    plgState->updateAFLBitmapSHM(m_aflBitmapSHM, pc);
}

void FuzzyS2E::onKernelFunctionExecutionStart(S2EExecutionState* state, KernelFunctionMonitor::KERNELFUNCS func)
{
    if (func != KernelFunctionMonitor::DO_EXIT) // focus on do_exit
        return;
    if(m_mainPid != state->getPid())
        return; // ignore other exit signal
    uint32_t code;
    state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &code, 4);
    s2e()->getDebugStream() << "[A] Process " << state->getPid() <<  " is unloading, code is " << code << "\n";
    if(WIFSIGNALED(code)){
        DECLARE_PLUGINSTATE(FuzzyS2EState, state);
        plgState->m_fault = FAULT_CRASH;
    }
    return;
}

bool FuzzyS2E::getAFLBitmapSHM()
{
    m_aflBitmapSHM = NULL;
    key_t shmkey;
    std::stringstream tracebits_strstream;
    tracebits_strstream << "/tmp/afltracebits/trace_" << m_QEMUPid;
    Path bitmap_file(tracebits_strstream.str().c_str());
    std::string errmsg;
    if(bitmap_file.createFileOnDisk(&errmsg)){
        s2e()->getDebugStream() << "FuzzyS2E: createFileOnDisk() error: "
                            << errmsg << "\n";
        exit(-1);
    }

    do {
        if ((shmkey = ftok(bitmap_file.c_str(), 1)) < 0) {
            s2e()->getDebugStream() << "FuzzyS2E: ftok() error: "
                    << strerror(errno) << "\n";
            return false;
        }
        int shm_id;
        try {
            shm_id = shmget(shmkey, AFL_BITMAP_SIZE, IPC_CREAT | 0600);
            if (shm_id < 0) {
                s2e()->getDebugStream() << "FuzzyS2E: shmget() error: "
                        << strerror(errno) << "\n";
                return false;
            }
            void * afl_area_ptr = shmat(shm_id, NULL, 0);
            if (afl_area_ptr == (void*) -1) {
                s2e()->getDebugStream() << "FuzzyS2E: shmat() error: "
                        << strerror(errno) << "\n";
                exit(1);
            }
            m_aflBitmapSHM = (unsigned char*) afl_area_ptr;
            m_findBitMapSHM = true;
            m_shmID = shm_id;
            if (m_verbose) {
                s2e()->getDebugStream() << "FuzzyS2E: Trace bits share memory id is "
                        << shm_id << "\n";
            }
        } catch (...) {
            return false;
        }
    } while (0);
    return true;
}

bool FuzzyS2E::initQemuQueue()
{
    int res;
    if (access(QEMUQUEUE, F_OK) == -1) {
        res = mkfifo(QEMUQUEUE, 0777);
        if (res != 0) {
            s2e()->getDebugStream() << "Could not create fifo " << QEMUQUEUE << ".\n";
            return false;
        }
    }
    m_queueFd = open(QEMUQUEUE, O_WRONLY | O_NONBLOCK);

    if (m_queueFd == -1)
    {
        s2e()->getDebugStream() << "Could not open fifo " << QEMUQUEUE << ".\n";
        return false;
    }
    // after the queue is initialized, write OK to FIFO
    assert(m_QEMUPid);
    char buffer[FIFOBUFFERSIZE + 1];
    memset(buffer, '\0', FIFOBUFFERSIZE + 1);
    sprintf(buffer, "%d|%d|%lu", m_QEMUPid, FAULT_NONE, (uint64_t)0);
    res = write(m_queueFd, buffer, FIFOBUFFERSIZE);
    if (res == -1)
    {
        s2e()->getDebugStream() << "Write error on pipe\n";
        exit(EXIT_FAILURE);
    }
    return true;
}

bool FuzzyS2E::initReadySHM()
{
    void *shm = NULL;
    int shmid;
    shmid = shmget((key_t) READYSHMID, sizeof(uint8_t)*65536, 0666);
    if (shmid == -1) {
        fprintf(stderr, "shmget failed\n");
        return false;
    }
    shm = shmat(shmid, (void*) 0, 0);
    if (shm == (void*) -1) {
        fprintf(stderr, "shmat failed\n");
        return false;
    }
    m_ReadyArray = (uint8_t*) shm;
    return true;
}

bool FuzzyS2E::generateCaseFile(S2EExecutionState *state,
        Path destfilename)
{
    //copy out template file to destination file
    Path template_file("/tmp/aa.jpeg");
    std::string errMsg;
    if (llvm::sys::CopyFile(destfilename, template_file, &errMsg)){
        s2e()->getDebugStream() << errMsg << "\n";
        s2e()->getDebugStream().flush();
        return false;
    }
    //try to solve the constraint and write the result to destination file
    int fd = open(destfilename.c_str(), O_RDWR);
    if (fd < 0) {
        s2e()->getDebugStream() << "could not open dest file: "
                << destfilename.c_str() << "\n";
        close(fd);
        return false;
    }
    /* Determine the size of the file */
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        s2e()->getDebugStream() << "could not determine the size of :"
                << destfilename.c_str() << "\n";
        close(fd);
        return false;
    }

    off_t offset = 0;
    std::string delim_str = "_";
    const char *delim = delim_str.c_str();
    char *p;
    char maxvarname[1024] = { 0 };
    ConcreteInputs out;
    //HACK: we have to create a new temple state, otherwise getting solution in half of a state may drive to crash
    klee::ExecutionState* exploitState = new klee::ExecutionState(*state);
    bool success = s2e()->getExecutor()->getSymbolicSolution(*exploitState,
            out);

    if (!success) {
        s2e()->getWarningsStream() << "Could not get symbolic solutions"
                << '\n';
        delete(exploitState);
        return false;
    }
    ConcreteInputs::iterator it;
    for (it = out.begin(); it != out.end(); ++it) {
        const VarValuePair &vp = *it;
        std::string varname = vp.first;
        // "__symfile___%s___%d_%d_symfile__value_%02x",filename, offset,size,buffer[buffer_i]);
        //parse offset
        strcpy(maxvarname, varname.c_str());
        if ((strstr(maxvarname, "symfile__value"))) {
            strtok(maxvarname, delim);
            strtok(NULL, delim);
            strtok(NULL, delim);
            //strtok(NULL, delim);
            p = strtok(NULL, delim);
            offset = atol(p);
            if (lseek(fd, offset, SEEK_SET) < 0) {
                s2e()->getDebugStream() << "could not seek to position : "
                        << offset << "\n";
                close(fd);
                delete(exploitState);
                return false;
            }
        } else if ((strstr(maxvarname, "___symfile___"))) {
            //v1___symfile___E:\case\huplayerpoc.m3u___27_2_symfile___0: 1a 00, (string) ".."
            //__symfile___%s___%d_%d_symfile__
            strtok(maxvarname, delim);
            strtok(NULL, delim);
            strtok(NULL, delim);
            //strtok(NULL, delim);
            p = strtok(NULL, delim);
            offset = atol(p);
            if (lseek(fd, offset, SEEK_SET) < 0) {
                s2e()->getDebugStream() << "could not seek to position : "
                        << offset << "\n";
                close(fd);
                delete(exploitState);
                return false;
            }
        } else {
            continue;
        }
        unsigned wbuffer[1] = { 0 };
        for (unsigned i = 0; i < vp.second.size(); ++i) {
            wbuffer[0] = (unsigned) vp.second[i];
            ssize_t written_count = write(fd, wbuffer, 1);
            if (written_count < 0) {
                s2e()->getDebugStream() << " could not write to file : "
                        << destfilename.c_str() << "\n";
                close(fd);
                delete(exploitState);
                return false;
            }
        }
    }
    close(fd);
    delete(exploitState);
    return true;
}

void FuzzyS2E::waitforafltestcase(void)
{
    char tmp[4];
    char err[128];
    int len;
    do{
        len = ::read(CTRLPIPE(m_QEMUPid), tmp, 4);
        if(len == -1){
            if(errno == EINTR)
                continue;
            break;
        }else
            break;

    } while(1);
    if (len != 4)
    {
        sprintf(err, "errno.%02d is: %s/n", errno, strerror(errno));
        s2e()->getDebugStream() << "FuzzyS2E: we cannot read pipe, length is " << len << ", error is "<< err << "\n";
        exit(2); // we want block here, why not ?
    }
}

// Write OK signal to queue to notify AFL that guest is ready (message is qemu's pid).
void FuzzyS2E::TellAFL(S2EExecutionState *state) // mark this as an atom procedure, i.e. should NOT be interrupted
{
    assert(!m_ReadyArray[m_QEMUPid] && "I'm free before? ");
    m_ReadyArray[m_QEMUPid] = 1;
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    assert(m_queueFd > 0 && "Haven't seen qemu queue yet?");
    char buffer[FIFOBUFFERSIZE + 1];
    memset(buffer, '\0', FIFOBUFFERSIZE + 1);
    if(!plgState->m_ExecTime){
        s2e()->getDebugStream() << "Cannot get execute time ?\n";
        s2e()->getDebugStream().flush();
        exit(EXIT_FAILURE);
    }
    uint64_t m_ellapsetime = plgState->m_ExecTime->check();
    sprintf(buffer, "%d|%d|%lu", m_QEMUPid, plgState->m_fault, m_ellapsetime);
    int res = write(m_queueFd, buffer, FIFOBUFFERSIZE);
    if (res == -1)
    {
        s2e()->getDebugStream() << "Write error on pipe, qemu is going to die...\n";
        s2e()->getDebugStream().flush();
        exit(EXIT_FAILURE);
    }
}

void FuzzyS2E::onCustomInstruction(
        S2EExecutionState *state,
        uint64_t operand
        )
{
    if (!OPCODE_CHECK(operand, AFLCONTROL_OPCODE)) {
        return;
    }

    uint64_t subfunction = OPCODE_GETSUBFUNCTION(operand);

    switch (subfunction) {
        case 0x0: {
            // Guest wants us to wait for AFL's testcase, so let's wait.
            waitforafltestcase();
            break;
        }
        case 0x1: {
            // Guest wants us to notify AFL that it has finished a test
            TellAFL(state);
            break;
        }
        default: {
            s2e()->getWarningsStream(state) << "Invalid FuzzyS2E opcode "
                    << hexval(operand) << '\n';
            break;
        }
    }

}


bool FuzzyS2EState::updateAFLBitmapSHM(unsigned char* AflBitmap,
        uint32_t curBBpc)
{
    uint32_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    if (cur_location >= AFL_BITMAP_SIZE)
        return false;
    AflBitmap[cur_location ^ m_prev_loc]++;
    m_prev_loc = cur_location >> 1;
    return true;
}

FuzzyS2EState::FuzzyS2EState()
{
    m_plugin = NULL;
    m_state = NULL;
    m_prev_loc = 0;
    m_ExecTime = new klee::WallTimer();
    m_fault = FAULT_NONE;
}

FuzzyS2EState::FuzzyS2EState(S2EExecutionState *s, Plugin *p)
{
    m_plugin = static_cast<FuzzyS2E*>(p);
    m_state = s;
    m_prev_loc = 0;
    if (m_ExecTime)
        delete m_ExecTime;
    m_ExecTime = new klee::WallTimer(); // we want a new timer
    m_fault = FAULT_NONE;
}

FuzzyS2EState::~FuzzyS2EState()
{
    if (m_ExecTime)
        delete m_ExecTime;
}

PluginState *FuzzyS2EState::clone() const
{
    return new FuzzyS2EState(*this);
}

PluginState *FuzzyS2EState::factory(Plugin *p, S2EExecutionState *s)
{
    FuzzyS2EState *ret = new FuzzyS2EState(s, p);
    return ret;
}
}
} /* namespace s2e */

