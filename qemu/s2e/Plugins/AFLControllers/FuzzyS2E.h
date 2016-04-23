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

#ifndef FUZZYS2E_H_

#define FUZZYS2E_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/FunctionMonitor.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/HostFiles.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <klee/Searcher.h>
#include <vector>
#include "klee/util/ExprEvaluator.h"
#include "AutoShFileGenerator.h"
#include <llvm/Support/TimeValue.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#define CONFIG_FUZZY

using namespace llvm::sys;
namespace s2e {
namespace plugins {
class FuzzyS2E;

class FuzzyS2EState: public PluginState
{
public:
    FuzzyS2E* m_plugin;
    S2EExecutionState *m_state;
public:
    //in order to improve efficiency, we write the branches of S2E to AFL's bitmap
    uint64_t m_prev_loc; //previous location when executing
    bool m_isTryState;
    FuzzyS2EState();
    FuzzyS2EState(S2EExecutionState *s, Plugin *p);
    virtual ~FuzzyS2EState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    inline bool updateAFLBitmapSHM(unsigned char* bitmap, uint64_t pc);

    inline void updateCaseGenetated(unsigned char* caseGenerated, uint64_t curBBpc);
    inline bool isfindNewBranch(unsigned char* CaseGenetated, unsigned char* Virgin_bitmap, uint64_t pc);

    friend class FuzzyS2E;
};

#define AFL_BITMAP_SIZE (1 << 16)

class FuzzyS2E: public Plugin, public klee::Searcher
{
S2E_PLUGIN

private:
    void onCustomInstruction(
            S2EExecutionState *state,
            uint64_t operand
            );
    void waitforafltestcase(void);
    bool generateCaseFile(S2EExecutionState *state, Path templatefile);
    inline bool findPathFast(S2EExecutionState *state);
    inline void replaceReadExprbyConstant(S2EExecutionState *state, klee::ref<klee::Expr> * expr, unsigned char *testcase, bool hasConst_Addr);
    std::set<int> m_fileLen;
public:
    struct SortById
    {
        bool operator ()(const klee::ExecutionState *_s1,
                const klee::ExecutionState *_s2) const
        {
            const S2EExecutionState *s1 =
                    static_cast<const S2EExecutionState*>(_s1);
            const S2EExecutionState *s2 =
                    static_cast<const S2EExecutionState*>(_s2);

            return s1->getID() < s2->getID();
        }
    };
    typedef std::set<klee::ExecutionState*, SortById> States;

    typedef std::vector< klee::ref<klee::Expr> > PathConstraint; // use path constraint to represent a path
    typedef std::set< PathConstraint >TouchedPaths;
    typedef std::map<uint64_t, TouchedPaths> size_TouchedPaths;

    typedef std::vector<uint64_t> ConstArray;

    std::vector<ConstArray> m_All_ConstArray;
    std::map<std::string, uint64_t> m_ConstArray_ALLIndex;

    size_TouchedPaths m_touched_Size_Paths;

    typedef std::set<std::string> StringSet;
    typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;
    ModuleExecutionDetector *m_detector;

    States m_normalStates;
    States m_speculativeStates;

    virtual klee::ExecutionState& selectState();
    virtual void update(klee::ExecutionState *current,
            const std::set<klee::ExecutionState*> &addedStates,
            const std::set<klee::ExecutionState*> &removedStates);

    bool empty();

public:
    /**
     * schdualer
     */
    unsigned char* m_aflBitmapSHM; //AFL's trace bits bitmap
    bool m_findBitMapSHM; //whether we have find trace bits bitmap

    unsigned char* m_aflVirginSHM; //AFL's virgin bits bitmap
    bool m_findVirginSHM; //whether we have find virgin bits bitmap
    std::string m_afl_initDir;   //AFL's initial directory
    // AFL end
    std::string m_mainModule;	//main module name (i.e. target binary)
    uint64_t m_mainPid;         //main process PID

    unsigned char m_caseGenetated[AFL_BITMAP_SIZE]; // branches we have generated case

    int m_shmID;
    int m_virgin_shmID;

    bool m_verbose; //verbose debug output

public:
    FuzzyS2E(S2E* s2e) :
            Plugin(s2e)
    {
        m_detector = NULL;
        m_shmID = 0;
        m_mainPid = 0;
        m_virgin_shmID = 0;
        m_aflBitmapSHM = 0;
        m_findBitMapSHM = false;
        m_aflVirginSHM = 0;
        m_findVirginSHM = false;
        m_verbose = false;
    }
    virtual ~FuzzyS2E();
    virtual void initialize();

    void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

    void onModuleTranslateBlockStart(ExecutionSignal*, S2EExecutionState*,
            const ModuleDescriptor &, TranslationBlock*, uint64_t);
    void onTranslateBlockStart(ExecutionSignal *signal,
            S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onStateFork(S2EExecutionState *state,
            const std::vector<S2EExecutionState*>& newStates,
            const std::vector<klee::ref<klee::Expr> >& newConditions);

    void onHandleForkAndConcretize(S2EExecutionState *state, klee::ref<klee::Expr> address);
    inline void fillConstArrayVector(S2EExecutionState *state, klee::ReadExpr* _read, ConstArray& CA);
    void onStateKill(S2EExecutionState *state);

    bool getAFLBitmapSHM();
    bool getAFLVirginSHM();

};
}
} /* namespace s2e */

#endif /* !FUZZYS2E_H_ */
