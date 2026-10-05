#ifndef IR_H
#define IR_H

#include <string>
#include <vector>
#include <set>

enum StmtType {
    STMT_ASSIGN,
    STMT_CALL,
    STMT_GOTO,
    STMT_RETURN,
    STMT_COND,
    STMT_PHI,
    STMT_OTHER
};

struct Statement {
    int id;
    std::string text;
    StmtType type;
};

struct BasicBlock {
    int id;
    std::vector<Statement> statements;
    std::vector<int> successors;
};

struct FunctionIR {
    std::string name;
    std::vector<Statement> preamble;
    std::vector<BasicBlock> blocks;
};

struct ProgramIR {
    std::vector<FunctionIR> functions;
};

extern ProgramIR program;

void applyGlobalDCE(ProgramIR& prog);

int get_first_stmt_id(const FunctionIR& func, int block_id);

bool hasSideEffect(const Statement& stmt);

void applyDCE(ProgramIR& prog);

void applyLocalDCE(FunctionIR& func);

std::string extractLHS(const std::string& text);
std::set<std::string> extractRHS(const std::string& text);
std::string sanitizeVar(std::string var);

#include <map>
void applyIntelligentDCE(ProgramIR& prog, const std::map<int, std::string>& dead_reasons);

void validate(const FunctionIR& func);
void repair_ssa_uses(FunctionIR& func, const std::string& dead_var, const std::string& replacement = "undef");
void fix_cfg_and_phis(FunctionIR& func, const std::set<int>& dead_blocks);

#endif