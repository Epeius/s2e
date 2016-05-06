/*
 * KernelFunctionMonitor.h
 *
 *  Created on: 2016年5月6日
 *      Author: epeius
 */

#ifndef KERNELFUNCTIONMONITOR_H_
#define KERNELFUNCTIONMONITOR_H_

#include <s2e/Plugins/ModuleDescriptor.h>
#include <s2e/Plugins/X86ExceptionInterceptor.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/OSMonitor.h>
#include <regex.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <map>

namespace s2e {
namespace plugins {


class KernelFunctionMonitor: public Plugin
{
    S2E_PLUGIN
public:
    enum KERNELFUNCS{
        DO_EXIT,
    };

protected:

    typedef struct _parse_expr
    {
        const char *name;
        const char *pattern; //regex to parse a line in a file (currently used for prelink-linux-<arch>.map
        regex_t *compiled_pattern;
    } parse_expr;

    typedef struct _symbol_struct
    {
        uint32_t adr;
        char type; //symbol type (T,D,...)
        std::string name;
        KERNELFUNCS func;
    } symbol_struct;

    typedef std::map<std::string, symbol_struct> SymbolTable;

private:
    typedef std::map<uint32_t, symbol_struct> kernel_symbols;
    kernel_symbols symbols;

    SymbolTable symboltable; //stores all kernel addresses of System.map

    void compilePattern(const char *pattern, regex_t *result);
    bool parseSystemMapFile(const char *system_map_file, SymbolTable &result);

public:
    KernelFunctionMonitor(S2E* s2e) :
        Plugin(s2e){};
    ~KernelFunctionMonitor();
    void initialize();

    bool searchSymbol(std::string symbolname, symbol_struct &result);

    void slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc, KERNELFUNCS func);
    void onTranslateBlockStart(ExecutionSignal*, S2EExecutionState *state,
            TranslationBlock *tb, uint64_t pc);
    // **** available signals ***
    sigc::signal<void,
                 S2EExecutionState*, /* currentState */
                 KERNELFUNCS> /* Function */
            onKernelFunctionExecutionStart;
};//class KernelFunctionMonitor

}// namespace plugins
} // namespace s2e

#endif /* KERNELFUNCTIONMONITOR_H_ */
