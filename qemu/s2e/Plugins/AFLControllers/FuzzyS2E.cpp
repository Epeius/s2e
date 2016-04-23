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
        "ModuleExecutionDetector", "HostFiles");

FuzzyS2E::~FuzzyS2E()
{
}
void FuzzyS2E::initialize()
{
    bool ok = false;
    std::string cfgkey = getConfigKey();
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
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onTranslateBlockStart));

    s2e()->getCorePlugin()->onCustomInstruction.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onCustomInstruction));
    s2e()->getCorePlugin()->onStateFork.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onStateFork));
    s2e()->getCorePlugin()->onStateKill.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onStateKill));
    s2e()->getCorePlugin()->onHandleForkAndConcretize.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onHandleForkAndConcretize));

    if (!m_findBitMapSHM)
        m_findBitMapSHM = getAFLBitmapSHM();
    if (!m_findVirginSHM)
        m_findVirginSHM = getAFLVirginSHM();
    assert(m_aflBitmapSHM && "AFL's trace bits bitmap is NULL, why??");
    assert(m_aflVirginSHM && "AFL's virgin bits bitmap is NULL, why??");

    memset(m_caseGenetated, 255, AFL_BITMAP_SIZE);
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

/*
 * When find a new branch, fuzzys2e will generate a testcase for afl.
 * Indeed, we should set SMT timeout so that we will not get stuck in symbex.
 */
void FuzzyS2E::onStateFork(S2EExecutionState *state,
        const std::vector<S2EExecutionState*>& newStates,
        const std::vector<klee::ref<klee::Expr> >& newConditions)
{
    assert(newStates.size() > 0);
    int origID = state->getID();
    if (!origID)
        return;
    int newStateIndex = (newStates[0]->getID() == origID) ? 1 : 0;
    S2EExecutionState *new_state = newStates[newStateIndex];
    DECLARE_PLUGINSTATE(FuzzyS2EState, new_state);
    plgState->m_isTryState = true;
    new_state->disableForking();
}


void FuzzyS2E::onStateKill(S2EExecutionState *state)
{
    int stateID = state->getID();
    if(stateID && !state->m_father->getID()){
        PathConstraint _PC;
        klee::ConstraintManager::constraint_iterator cit = state->constraints.begin();
        s2e()->getDebugStream(state) << "=========================\n";
        int i = 0;
        while(i < stateID){
            cit++;
            i++;
        }
        for(; cit != state->constraints.end(); cit++){
            _PC.push_back(*cit);
            s2e()->getDebugStream(state) << *cit << "\n";
        }
        s2e()->getDebugStream(state) << "=========================\n";
        s2e()->getDebugStream(state).flush();
        if (_PC.size() && state->m_symFileLen) {
            if (m_touched_Size_Paths.find(state->m_symFileLen) == m_touched_Size_Paths.end()) {
                TouchedPaths _tp;
                _tp.insert(_PC);
                m_touched_Size_Paths.insert(
                        std::make_pair(state->m_symFileLen, _tp));
            } else {
                TouchedPaths _tp = m_touched_Size_Paths[state->m_symFileLen];
                m_touched_Size_Paths.erase(state->m_symFileLen);
                _tp.insert(_PC);
                m_touched_Size_Paths[state->m_symFileLen] = _tp;
            }
        }
        if(stateID == 1) // we only do it once
            state->m_father->m_strSymFileName = state->m_strSymFileName;
    }
}

void FuzzyS2E::fillConstArrayVector(S2EExecutionState *state, klee::ReadExpr* _read, ConstArray& CA)
{
    assert(_read->updates.root->name.compare("const_arr")>0);
    const std::vector< klee::ref<klee::ConstantExpr> > _constantValues = _read->updates.root->constantValues;
    /*
    do {
        int i = 0;
        s2e()->getDebugStream() << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
        for (; i < _read->updates.root->size; i++) {
            klee::ref<klee::ConstantExpr> _tmp =
                    _read->updates.root->constantValues[i];
            s2e()->getDebugStream() << _tmp;
            if(!((i+1)%4))
                s2e()->getDebugStream() << "\n";
        }
        s2e()->getDebugStream() << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
    } while (0);
    */

    int i = 0;
    while(i<_read->updates.root->size){
        klee::ConstantExpr *ce_0 = dyn_cast<klee::ConstantExpr>(_constantValues[i]);
        klee::ConstantExpr *ce_1 = dyn_cast<klee::ConstantExpr>(_constantValues[i+1]);
        klee::ConstantExpr *ce_2 = dyn_cast<klee::ConstantExpr>(_constantValues[i+2]);
        klee::ConstantExpr *ce_3 = dyn_cast<klee::ConstantExpr>(_constantValues[i+3]);
        uint64_t i_ce_0 =  ce_0->getZExtValue();
        uint64_t i_ce_1 =  ce_1->getZExtValue();
        uint64_t i_ce_2 =  ce_2->getZExtValue();
        uint64_t i_ce_3 =  ce_3->getZExtValue();
        CA.push_back((i_ce_3 << 24) + (i_ce_2 << 16) + (i_ce_1 << 8) + i_ce_0); // we currently only support x86
        i+=4;
    }
}

//HACK: Read the constant array.
void FuzzyS2E::onHandleForkAndConcretize(S2EExecutionState *state, klee::ref<klee::Expr> address)
{
    int n = address.get()->getNumKids();
    for (int i = 0; i < n; i++ ){
        klee::ref<klee::Expr> kid = address.get()->getKid(i);
        s2e()->getDebugStream() << "onHandleForkAndConcretize: kid is " << *(kid.get()) << "\n";
        /*
        if(kid->getKind() == klee::Expr::Read){
            s2e()->getDebugStream() << "we are handling " << kid << " and CUR_CONSTARR width is " << kid.get()->getWidth() << "\n";
            klee::ReadExpr *read = dyn_cast<klee::ReadExpr>(kid);
            assert(read && "Cannot get Read expression?");
            if(read->updates.root->name.compare("const_arr")>0){
                klee::ref<klee::Expr> __index = state->concolics.evaluate(read->index.get()->getKid(1));
                s2e()->getDebugStream() << "INDEX is " << __index << "\n";
                if(m_ConstArray_ALLIndex.find(read->updates.root->name) != m_ConstArray_ALLIndex.end())
                    return;
                if(read->updates.root->isConstantArray()){
                    ConstArray _CA;
                    fillConstArrayVector(state,  read, _CA);
                    int CA_it_index = 0;
                    std::vector<ConstArray>::iterator CA_it = m_All_ConstArray.begin();
                    for(; CA_it != m_All_ConstArray.end(); CA_it++, CA_it_index++){
                        ConstArray __CA__ = *CA_it;
                        if(__CA__ == _CA)
                            break;
                    }
                    if(CA_it == m_All_ConstArray.end())
                        m_All_ConstArray.push_back(_CA);
                    m_ConstArray_ALLIndex.insert(std::make_pair(read->updates.root->name, CA_it_index));
                }
            }

        }

        onHandleForkAndConcretize(state, kid);
        */

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
 /*
    if (m_mainModule == mod.Name) {
        es->connect(
        sigc::mem_fun(*this, &FuzzyS2E::slotExecuteBlockStart));
    }
   */
    if(m_mainModule == mod.Name){
        m_mainPid = state->getPid();
    }

}

void FuzzyS2E::onTranslateBlockStart(ExecutionSignal *signal,
        S2EExecutionState *state, TranslationBlock *tb, uint64_t pc)
{
    if (!tb) {
        return;
    }
    if(pc < 0xc0000000)// FIXME: we do non't want to check kernel ?
        signal->connect(sigc::mem_fun(*this, &FuzzyS2E::slotExecuteBlockStart));
}


/**
 */
void FuzzyS2E::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    if(!m_mainPid || state->getPid() != m_mainPid)
        return;
    // do work here.
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    if (!plgState->m_isTryState)
        plgState->updateAFLBitmapSHM(m_aflBitmapSHM, pc);
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

bool FuzzyS2E::getAFLBitmapSHM()
{
    m_aflBitmapSHM = NULL;
    key_t shmkey;
    do {
        if ((shmkey = ftok("/tmp/aflbitmap", 1)) < 0) {
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

bool FuzzyS2E::getAFLVirginSHM()
{
    m_aflVirginSHM = NULL;
    key_t shmkey;
    do {
        if ((shmkey = ftok("/tmp/aflvirgin", 'a')) < 0) {
            s2e()->getDebugStream() << "FuzzyS2E: ftok() error: "
                    << strerror(errno) << "\n";
            return false;
        }
        int shm_id;
        try {
            shm_id = shmget(shmkey, AFL_BITMAP_SIZE, 0600);
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
            m_aflVirginSHM = (unsigned char*) afl_area_ptr;
            m_findVirginSHM = true;
            m_virgin_shmID = shm_id;
            if (m_verbose) {
                s2e()->getDebugStream() << "FuzzyS2E: Virgin bits share memory id is "
                        << shm_id << "\n";
            }
        } catch (...) {
            s2e()->getDebugStream() << "FuzzyS2E: getAFLVirginSHM failed, unknown reason.\n";
            return false;
        }
    } while (0);
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
wait:
    do{
        len = ::read(AFLS2EHOSTPIPE_AFL, tmp, 4);
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
    if(findPathFast(g_s2e_state)){
        char tmp[4];
        tmp[0] = 'n';
        tmp[1] = 'u';
        tmp[2] = 'd';
        tmp[3] = 't';
        write(AFLS2EHOSTPIPE_S2E + 1, tmp, sizeof(tmp)); // tell AFL we have finish a test procedure
        goto wait;
    }else{
        s2e()->getDebugStream() << "May find a new branch testcase?"<< '\n';
    }
}

void FuzzyS2E::replaceReadExprbyConstant(S2EExecutionState *state, klee::ref<klee::Expr> * expr, unsigned char *testcase, bool hasConst_Addr)
{
    int n = expr->get()->getNumKids();
    klee::ref<klee::Expr> *kids = new klee::ref<klee::Expr> [n];
    for (int i = 0; i < n; i++) {
        klee::ref<klee::Expr> kid = expr->get()->getKid(i);
        if(kid->getKind() == klee::Expr::Read){
            klee::ReadExpr *read = dyn_cast<klee::ReadExpr>(expr->get()->getKid(i));
            assert(read && "Cannot get Read expression?");
            if(read->updates.root->name.compare("const_arr")>0){ //FIXME: hack here, don't know why
                hasConst_Addr = true;
                read->print(s2e()->getDebugStream());
                if(read->updates.root->isSymbolicArray()){
                    s2e()->getDebugStream() << "read is symbolic array\n";
                }else if(read->updates.root->isConstantArray()){
                    klee::ref<klee::Expr> evalResult = state->concolics.evaluate(read->index);
                    klee::ConstantExpr *index = dyn_cast<klee::ConstantExpr>(evalResult);
                    s2e()->getDebugStream() << "read is constant array, and index is \n";
                    if (index)
                        index->print(s2e()->getDebugStream());
                    else
                        evalResult.get()->print(s2e()->getDebugStream());
                    s2e()->getDebugStream() << "\n";
                    int i = 0;
                    for(; i < read->updates.root->size; i++){
                        klee::ref<klee::ConstantExpr> _tmp = read->updates.root->constantValues[i];
                        s2e()->getDebugStream() << _tmp;
                    }
                    s2e()->getDebugStream() << "constant array read end\n";
                }
                return;
            }
        }
        if(kid->getNumKids())
            replaceReadExprbyConstant(state, &kid, testcase, hasConst_Addr);
        if(kid->getKind() == klee::Expr::Read){
            klee::ReadExpr *read = dyn_cast<klee::ReadExpr>(expr->get()->getKid(i));
            klee::ConstantExpr *index = dyn_cast<klee::ConstantExpr>(read->index);
            klee::ref<klee::ConstantExpr> testcase_byte = klee::ConstantExpr::create(testcase[index->getZExtValue()], read->getWidth());
            kids[i] = testcase_byte;
        }else{
            kids[i] = kid;
        }

    }
    *expr = expr->get()->rebuild(kids);
//    delete kids;
}

bool FuzzyS2E::findPathFast(S2EExecutionState *state)
{
    Path template_file("/tmp/aa.jpeg");
    //try to solve the constraint and write the result to destination file
    int fd = open(template_file.c_str(), O_RDWR);
    if (fd < 0) {
        s2e()->getDebugStream() << "could not open dest file: "
                << template_file.c_str() << "\n";
        close(fd);
        return false;
    }
    /* Determine the size of the file */
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        s2e()->getDebugStream() << "could not determine the size of :"
                << template_file.c_str() << "\n";
        close(fd);
        return false;
    }
    if(m_touched_Size_Paths.find(size) == m_touched_Size_Paths.end()){
        close(fd);
        s2e()->getDebugStream() << "Try to dry run because it is a new file size: " << size << "\n";
        return false;
    }
    lseek(fd, 0, SEEK_SET);
    unsigned char *testcase = new unsigned char [size];
    ::read(fd, testcase, size);
    close(fd);

    std::set<PathConstraint>::iterator it_path;
    TouchedPaths touched_paths = m_touched_Size_Paths[size];

    for(it_path = touched_paths.begin(); it_path != touched_paths.end(); it_path++){
        PathConstraint _curPath = *it_path;
        std::vector< klee::ref<klee::Expr> >::iterator it_condition = _curPath.begin();
        for(; it_condition != _curPath.end(); it_condition++){
            klee::ref<klee::Expr> _condition = *it_condition;
            bool hasConst_Addr = false;
            replaceReadExprbyConstant(state, &_condition, testcase, hasConst_Addr);
            if(hasConst_Addr)
                continue;
            else{
                klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(_condition);
//                assert(ce && "Could not evaluate the expression to a constant.");
                if (!ce) {
                    s2e()->getDebugStream()
                            << "Could not evaluate the expression: "
                            << _condition << "\n";
                    s2e()->getDebugStream().flush();
                    continue;
                }
                if (ce->isTrue()) {
                    //satisfy this branch, let's get next branch
                    continue;
                } else {
                    //let's get another path to test
                    break;
                }
            }
        }
        if(it_condition == _curPath.end()){// found a touched path
            delete testcase;
            return true;
        }
    }
    delete testcase;
    s2e()->getDebugStream() << "********************************************\n";
    s2e()->getDebugStream().flush();
    return false;
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

    switch(subfunction) {
        case 0: {
            // Guest wants us to wait for AFL's testcase, so let's wait.
                waitforafltestcase();
                break;
            }
        default: {
                s2e()->getWarningsStream(state)
                        << "Invalid FuzzyS2E opcode " << hexval(operand)  << '\n';
                break;
        }
    }

}



void FuzzyS2EState::updateCaseGenetated(unsigned char* caseGenerated,
        uint64_t curBBpc)
{
    uint64_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    if (cur_location >= AFL_BITMAP_SIZE)
        return;
    caseGenerated[cur_location ^ m_prev_loc] = 0;
    m_prev_loc = cur_location >> 1;
}

bool FuzzyS2EState::updateAFLBitmapSHM(unsigned char* AflBitmap,
        uint64_t curBBpc)
{
    uint64_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    if (cur_location >= AFL_BITMAP_SIZE)
        return false;
    AflBitmap[cur_location ^ m_prev_loc]++;
    m_prev_loc = cur_location >> 1;
    return true;
}

/*
  There are two types of old branch:
  1. Forked and case-generated by S2E
  2. Executed by S2E/AFL
 */
bool FuzzyS2EState::isfindNewBranch(unsigned char* CaseGenetated, unsigned char* Virgin_bitmap,
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

FuzzyS2EState::FuzzyS2EState()
{
    m_plugin = NULL;
    m_state = NULL;
    m_prev_loc = 0;
    m_isTryState = false;
}

FuzzyS2EState::FuzzyS2EState(S2EExecutionState *s, Plugin *p)
{
    m_plugin = static_cast<FuzzyS2E*>(p);
    m_state = s;
    m_prev_loc = 0;
    m_isTryState = false;
}

FuzzyS2EState::~FuzzyS2EState()
{
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
