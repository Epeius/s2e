/*
 * KernelFunctionMonitor.cpp
 *
 *  Created on: 2016年5月6日
 *      Author: epeius
 */
#include "KernelFunctionMonitor.h"

extern "C" {
#include "config.h"
#include <regex.h>
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include <sysemu.h>
#include <sys/shm.h>
}
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
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

#define READCONFIG_INT(C) C = s2e()->getConfig()->getInt(getConfigKey() + "." + #C)
#define IMPORT_SYMBOL(NAME,SYMBOLS, FUNC)                                                                   \
        do{                                                                                                 \
            symbol_struct temp;                                                                             \
            if (!searchSymbol(NAME,temp)) {                                                                 \
                s2e()->getWarningsStream() << "Symbol " << #NAME << " not found in System.map.\n";          \
                ::exit(1);                                                                                  \
            }                                                                                               \
            temp.func = FUNC;                                                                               \
            SYMBOLS.insert(std::make_pair(temp.adr, temp));                                                 \
        }while(0);

using namespace std;

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(KernelFunctionMonitor, "Plugin for monitoring Linux events", "S2E_NOOP");

KernelFunctionMonitor::~KernelFunctionMonitor()
{
}

void KernelFunctionMonitor::initialize()
{
    bool ok = false;
    const char *system_map_file = s2e()->getConfig()->getString(getConfigKey() + ".system_map_file", "", &ok).c_str();
    if (!ok) {
        s2e()->getWarningsStream()
                << "No System.map file provided. System.map is needed for Kernel Function Monitor to work properly. Quit."
                << "\n";
        ::exit(-1);   // call system to stop
    }

    if (!parseSystemMapFile(system_map_file, symboltable)) {
        ::exit(1);
    }

    // read important kernel symbols from System.map
    IMPORT_SYMBOL("do_exit", symbols, DO_EXIT);

    // **** signal connecting ***
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this,
                    &KernelFunctionMonitor::onTranslateBlockStart));
}

void KernelFunctionMonitor::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc, KERNELFUNCS func)
{
    switch (func) {
        case DO_EXIT:
            onKernelFunctionExecutionStart.emit(state, DO_EXIT);
            if (0) {
                uint32_t code;
                state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &code, 4);
                s2e()->getDebugStream() << "[A] Process " << state->getPid() << " is unloading, code is " << code << "\n";
                if (WIFSIGNALED(code))
                    s2e()->getDebugStream() << "[B] Process " << state->getPid() << " is CRASH.\n";
            }
            break;
        default:
            break;
    }
}
void KernelFunctionMonitor::onTranslateBlockStart(ExecutionSignal *signal,
        S2EExecutionState *state, TranslationBlock *tb, uint64_t pc)
{
    kernel_symbols::iterator it;
    it = symbols.find((uint32_t)pc);
    if (it == symbols.end()) {
        return;
    }
    signal->connect(sigc::bind(sigc::mem_fun(*this, &KernelFunctionMonitor::slotExecuteBlockStart), it->second.func));
}

bool KernelFunctionMonitor::searchSymbol(std::string name, symbol_struct &result)
{
    SymbolTable::iterator it;
    it = symboltable.find(name);

    if (it == symboltable.end()) {
        return false;
    }

    result = it->second;
    return true;

}

bool KernelFunctionMonitor::parseSystemMapFile(const char *system_map_file, SymbolTable &result)
{
    parse_expr pattern =
    { "symbol_entry", "(^[[:xdigit:]]{8,8}) (.) (.*)$", NULL };

    //open file
    std::ifstream system_map_stream;
    system_map_stream.open(system_map_file);
    if (!system_map_stream) {
        s2e()->getWarningsStream()
                << "KernelFunctionMonitor:: Unable to open System.map file"
                << system_map_file << ".\n";
        ::exit(1);   // call system to stop
    }

    pattern.compiled_pattern = (regex_t*) malloc(sizeof(regex_t));
    compilePattern(pattern.pattern, pattern.compiled_pattern);

    char line[255];
    size_t nmatch = 4;
    regmatch_t matchptr[nmatch];
    int regret;

    while (system_map_stream) {
        system_map_stream.getline(line, 255);
        regret = regexec(pattern.compiled_pattern, line, nmatch, matchptr, 0);
        if (0 == regret) {
            //match, get the subexpressions
            size_t adr_len = matchptr[1].rm_eo - matchptr[1].rm_so;
            size_t type_len = matchptr[2].rm_eo - matchptr[2].rm_so;
            size_t name_len = matchptr[3].rm_eo - matchptr[3].rm_so;

            char *s_adr = new char[adr_len + 1];
            char * s_type = new char[type_len + 1];
            char *s_name = new char[name_len + 1];

            strncpy(s_adr, (line + matchptr[1].rm_so), adr_len);
            strncpy(s_type, (line + matchptr[2].rm_so), type_len);
            strncpy(s_name, (line + matchptr[3].rm_so), name_len);

            s_adr[adr_len] = '\0';
            s_type[type_len] = '\0';
            s_name[name_len]='\0';
            symbol_struct sym;
            sym.adr = (uint32_t) strtoul(s_adr, NULL, 16);
            sym.type = s_type[0];
            std::string name = std::string(s_name);
            sym.name = name;

            result[name] = sym; //insert

            delete[] s_adr;
            delete[] s_type;
            delete[] s_name;

        } else if (REG_NOMATCH == regret) {
            continue;
        } else {
            size_t length = regerror(regret, pattern.compiled_pattern, NULL, 0);
            char *buffer = (char*) malloc(length);
            (void) regerror(regret, pattern.compiled_pattern, buffer, length);
            s2e()->getWarningsStream()
                    << "KernelFunctionMonitor::parseSystemMap: Error matching regex. msg: "
                    << buffer << ".\n";
            return false;
        }
    }

    regfree(pattern.compiled_pattern);
    free(pattern.compiled_pattern);

    s2e()->getMessagesStream() << "KernelFunctionMonitor:: successfully parsed " << symboltable.size() << " symbols from System.map.\n";

    system_map_stream.close();
    return true;
}

void KernelFunctionMonitor::compilePattern(const char *pattern, regex_t *result)
{
    int regret;
    regret = regcomp(result, pattern, REG_ICASE | REG_EXTENDED);
    if (regret != 0) {
        size_t length = regerror(regret, result, NULL, 0);
        char *buffer = (char*) malloc(length);
        (void) regerror(regret, result, buffer, length);
        s2e()->getWarningsStream() << "KernelFunctionMonitor:: Error compiling regex "
                << pattern << " msg: " << buffer << ".\n";
        ::exit(-1);   // call system to stop
    }
}
