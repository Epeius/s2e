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

#include "FuzzyStuckHelper.h"
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

S2E_DEFINE_PLUGIN(FuzzyStuckHelper, "FuzzyStuckHelper plugin", "FuzzyStuckHelper",
        "ModuleExecutionDetector", "HostFiles");

FuzzyStuckHelper::~FuzzyStuckHelper()
{
}
void FuzzyStuckHelper::initialize()
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
                                        sigc::mem_fun(*this, &FuzzyStuckHelper::onModuleTranslateBlockStart));
    s2e()->getCorePlugin()->onCustomInstruction.connect(
                                        sigc::mem_fun(*this, &FuzzyStuckHelper::onCustomInstruction));
    s2e()->getCorePlugin()->onStateFork.connect(
                                            sigc::mem_fun(*this, &FuzzyStuckHelper::onStateFork));
    m_QEMUPid = getpid();
    if (!m_findVirginSHM)
        m_findVirginSHM = getAFLVirginSHM();
    assert(m_aflVirginSHM && "AFL's virgin bits bitmap is NULL, why??");

    std::stringstream testcase_strstream;
    testcase_strstream << "/tmp/afltestcase/" << m_QEMUPid;
    if (::access(testcase_strstream.str().c_str(), F_OK)) // for all testcases
        mkdir(testcase_strstream.str().c_str(), 0777);
    if(!m_HostFiles->addDirectories(testcase_strstream.str()))
        exit(EXIT_FAILURE);
    memset(m_caseGenetated, 255, AFL_BITMAP_SIZE);
    s2e()->getExecutor()->setSearcher(this);
}

//return *states[theRNG.getInt32()%states.size()];

klee::ExecutionState& FuzzyStuckHelper::selectState()
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

void FuzzyStuckHelper::update(klee::ExecutionState *current,
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

bool FuzzyStuckHelper::empty()
{
    return m_normalStates.empty() && m_speculativeStates.empty();
}


void FuzzyStuckHelper::onModuleTranslateBlockStart(ExecutionSignal* es,
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
        sigc::mem_fun(*this, &FuzzyStuckHelper::slotExecuteBlockStart));
    }

}

/**
 */
void FuzzyStuckHelper::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    if (!state->getID())
        return;
    if (pc > 0xc000000) // Ignore kernel module in order to compare with vanilla AFL
        return;
    DECLARE_PLUGINSTATE(FuzzyStuckHelperState, state);
    if (!plgState->m_isTryState)
        plgState->updatePre_loc(pc);
    else {
        /* If current state is a new created try state, we first decide whether this
         branch has been covered, if yes, forget it, otherwise we generate a new testcase.
         Then kill this state, let the scheduler select the original state. */
        if (plgState->isfindNewBranch(m_caseGenetated, m_aflVirginSHM, pc)) {
            std::stringstream str_dstFile;
            str_dstFile << m_afl_initDir << "/" << state->getID(); // str_dstFile = /path/to/afl/initDir/ID
            Path dstFile(str_dstFile.str());
            std::string errMsg;
            if (dstFile.createFileOnDisk(&errMsg)) {
                s2e()->getDebugStream() << errMsg << "\n";
                s2e()->getDebugStream().flush();
            } else {
                if(generateCaseFile(state, dstFile)){
                    // after we successfully generate the testcase, we should record it.
                    state->m_father->m_forkedfromMe++;
                    plgState->updateCaseGenetated(m_caseGenetated, pc);
                }
            }
        }
        // As we have defined the searcher's behavior, so after we terminate this state, the non-zero state will be selected.
        s2e()->getExecutor()->terminateStateEarly(*state, "FuzzySearcher: terminate this for fuzzing");
    }
}

/*
 * When find a new branch, fuzzys2e will generate a testcase for afl.
 * Indeed, we should set SMT timeout so that we will not get stuck in symbex.
 */
void FuzzyStuckHelper::onStateFork(S2EExecutionState *state,
        const std::vector<S2EExecutionState*>& newStates,
        const std::vector<klee::ref<klee::Expr> >& newConditions)
{
    assert(newStates.size() > 0);
    int origID = state->getID();
    if (!origID)
        return;
    int newStateIndex = (newStates[0]->getID() == origID) ? 1 : 0;
    S2EExecutionState *new_state = newStates[newStateIndex];
    DECLARE_PLUGINSTATE(FuzzyStuckHelperState, new_state);
    plgState->m_isTryState = true;
    new_state->disableForking();
}


bool FuzzyStuckHelper::getAFLVirginSHM()
{
    m_aflVirginSHM = NULL;
    key_t shmkey;
    do {
        if ((shmkey = ftok("/tmp/aflvirgin", 'a')) < 0) {
            s2e()->getDebugStream() << "FuzzyStuckHelper: ftok() error: "
                    << strerror(errno) << "\n";
            return false;
        }
        int shm_id;
        try {
            shm_id = shmget(shmkey, AFL_BITMAP_SIZE, 0600);
            if (shm_id < 0) {
                s2e()->getDebugStream() << "FuzzyStuckHelper: shmget() error: "
                        << strerror(errno) << "\n";
                return false;
            }
            void * afl_area_ptr = shmat(shm_id, NULL, 0);
            if (afl_area_ptr == (void*) -1) {
                s2e()->getDebugStream() << "FuzzyStuckHelper: shmat() error: "
                        << strerror(errno) << "\n";
                exit(1);
            }
            m_aflVirginSHM = (unsigned char*) afl_area_ptr;
            m_findVirginSHM = true;
            m_virgin_shmID = shm_id;
            if (m_verbose) {
                s2e()->getDebugStream() << "FuzzyStuckHelper: Virgin bits share memory id is "
                        << shm_id << "\n";
            }
        } catch (...) {
            s2e()->getDebugStream() << "FuzzyStuckHelper: getAFLVirginSHM failed, unknown reason.\n";
            return false;
        }
    } while (0);
    return true;
}


bool FuzzyStuckHelper::generateCaseFile(S2EExecutionState *state,
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

void FuzzyStuckHelper::waitforafltestcase(void)
{
    char tmp[4];
    char err[128];
    int len;
    do{
        len = ::read(AFLCTRLPIPE, tmp, 4);
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
void FuzzyStuckHelper::TellAFL(S2EExecutionState *state)
{
    char tmp[4];
    tmp[0] = 'n';
    tmp[1] = 'u';
    tmp[2] = 'd';
    tmp[3] = 't';
    int res = write(S2ECTRLPIPE + 1, tmp, sizeof(tmp)); // tell AFL we have finish a test procedure
    s2e()->getMessagesStream(state) << "I have told AFL that I am done, so what?"<< '\n';
    if (res == -1)
    {
        s2e()->getDebugStream() << "Write error on pipe, qemu is going to die...\n";
        s2e()->getDebugStream().flush();
        exit(EXIT_FAILURE);
    }
}

void FuzzyStuckHelper::onCustomInstruction(
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
            s2e()->getWarningsStream(state) << "Invalid FuzzyStuckHelper opcode "
                    << hexval(operand) << '\n';
            break;
        }
    }

}


void FuzzyStuckHelperState::updateCaseGenetated(unsigned char* caseGenerated,
        uint64_t curBBpc)
{
    uint64_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    if (cur_location >= AFL_BITMAP_SIZE)
        return;
    caseGenerated[cur_location ^ m_prev_loc] = 0;
    m_prev_loc = cur_location >> 1;
}

bool FuzzyStuckHelperState::updatePre_loc(uint32_t curBBpc)
{
    uint32_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    if (cur_location >= AFL_BITMAP_SIZE)
        return false;
    m_prev_loc = cur_location >> 1;
    return true;
}

/*
  There are two types of old branch:
  1. Forked and case-generated by S2E
  2. Executed by S2E/AFL
 */
bool FuzzyStuckHelperState::isfindNewBranch(unsigned char* CaseGenetated, unsigned char* Virgin_bitmap,
        uint64_t curBBpc)
{
    uint64_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    g_s2e->getDebugStream() << "cur_location is " << cur_location << ", and virgin map here is " << hexval(Virgin_bitmap[cur_location ^ m_prev_loc]) <<
            ", and CaseGenetated here is " << hexval(CaseGenetated[cur_location ^ m_prev_loc]) << "\n";
    if (cur_location >= AFL_BITMAP_SIZE)
        return false;
    return Virgin_bitmap[cur_location ^ m_prev_loc] && CaseGenetated[cur_location ^ m_prev_loc];
}

FuzzyStuckHelperState::FuzzyStuckHelperState()
{
    m_plugin = NULL;
    m_state = NULL;
    m_prev_loc = 0;
    m_isTryState = false;
}

FuzzyStuckHelperState::FuzzyStuckHelperState(S2EExecutionState *s, Plugin *p)
{
    m_plugin = static_cast<FuzzyStuckHelper*>(p);
    m_state = s;
    m_prev_loc = 0;
    m_isTryState = false;
}

FuzzyStuckHelperState::~FuzzyStuckHelperState()
{
}

PluginState *FuzzyStuckHelperState::clone() const
{
    return new FuzzyStuckHelperState(*this);
}

PluginState *FuzzyStuckHelperState::factory(Plugin *p, S2EExecutionState *s)
{
    FuzzyStuckHelperState *ret = new FuzzyStuckHelperState(s, p);
    return ret;
}
}
} /* namespace s2e */
