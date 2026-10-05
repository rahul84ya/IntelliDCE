#include "ir.h"
#include <iostream>
#include <regex>
#include <set>
#include <algorithm>
#include <queue>
#include <map>
#include <string>

std::string sanitizeVar(std::string var) {
    var.erase(std::remove_if(var.begin(), var.end(), [](char c) {
        return !(isalnum(c) || c == '_' || c == '.');
    }), var.end());
    return var;
}

bool hasSideEffect(const Statement& stmt) {
    if (stmt.type == STMT_CALL) {
        std::regex sys_call(R"(\b(printf|scanf|malloc|free|fopen|fclose|fwrite|fread|sys_.*)\b)");
        if (std::regex_search(stmt.text, sys_call)) return true;
        // Standard C++ IO and side-effecting symbols
        if (stmt.text.find("std::cout") != std::string::npos) return true;
        if (stmt.text.find("std::ostream") != std::string::npos) return true;
        if (stmt.text.find("operator<<") != std::string::npos) return true;
        if (stmt.text.find("endl") != std::string::npos) return true;
    }
    return false;
}

void repair_ssa_uses(FunctionIR& func, const std::string& dead_var, const std::string& replacement /* = "undef" */) {
    std::regex var_re("\\b" + dead_var + "\\b");
    for (auto& block : func.blocks) {
        for (auto& stmt : block.statements) {
            auto uses = extractRHS(stmt.text);
            if (uses.count(dead_var)) {
                stmt.text = std::regex_replace(stmt.text, var_re, replacement);
            }
        }
    }
}

void fix_cfg_and_phis(FunctionIR& func, const std::set<int>& dead_blocks) {
    for (auto& block : func.blocks) {
        if (dead_blocks.count(block.id)) continue;
        
        // 1. Remove dead successors
        block.successors.erase(
            std::remove_if(block.successors.begin(), block.successors.end(),
                           [&](int succ) { return dead_blocks.count(succ); }),
            block.successors.end());
            
        // 2. Fix PHI nodes
        auto it = block.statements.begin();
        while (it != block.statements.end()) {
            if (it->type == STMT_PHI) {
                std::string text = it->text;
                bool modified = false;
                for (int d_bb : dead_blocks) {
                    std::string arg = "(" + std::to_string(d_bb) + ")";
                    size_t pos = text.find(arg);
                    if (pos != std::string::npos) {
                        size_t start = pos;
                        while (start > 0 && text[start-1] != '<' && text[start-1] != ' ') start--;
                        size_t end = pos + arg.length();
                        while (end < text.length() && text[end] != ',' && text[end] != '>') end++;
                        if (end < text.length() && text[end] == ',') end++; // consume comma
                        else if (text[end] == '>' && text[start-1] == ',') start--; // consume leading comma
                        text.erase(start, end - start);
                        modified = true;
                    }
                }
                
                if (text.find("<>") != std::string::npos || text.find("PHI >") != std::string::npos || text.find("PHI <>") != std::string::npos || text.find("< >") != std::string::npos) {
                    std::string target = extractLHS(text);
                    if (!target.empty()) repair_ssa_uses(func, target, "undef");
                    it = block.statements.erase(it);
                    continue;
                } else if (modified) {
                    it->text = text;
                }
            }
            ++it;
        }
    }
}

void validate(const FunctionIR& func) {
    if (func.blocks.empty()) return;
    
    std::set<int> valid_blocks;
    for (const auto& b : func.blocks) if (!b.statements.empty() || !b.successors.empty()) valid_blocks.insert(b.id);
    // 1 always counts as entry point so include empty entry just to be safe
    valid_blocks.insert(func.blocks[0].id);

    std::set<int> reachable;
    std::queue<int> q;
    q.push(func.blocks[0].id);
    reachable.insert(func.blocks[0].id);
    while (!q.empty()) {
        int curr = q.front(); q.pop();
        for (const auto& b : func.blocks) {
            if (b.id == curr) {
                for (int s : b.successors) {
                    if (valid_blocks.find(s) == valid_blocks.end()) {
                        std::cerr << "[Validation: Error] Dangling edge from BB " << curr << " to BB " << s << "\n";
                    } else if (reachable.find(s) == reachable.end()) {
                        reachable.insert(s);
                        q.push(s);
                    }
                }
            }
        }
    }
    
    std::set<std::string> defined_vars;
    for (const auto& bb : func.blocks) {
        for (const auto& stmt : bb.statements) {
            std::string lhs = extractLHS(stmt.text);
            if (!lhs.empty()) defined_vars.insert(lhs);
            for (const auto& rhs : extractRHS(stmt.text)) {
                if (rhs != "undef" && !isdigit(rhs[0]) && !defined_vars.count(rhs)) {
                    std::cerr << "[Validation: Info] Potential use of undefined/external var: " << rhs << " in BB " << bb.id << "\n";
                }
            }
        }
    }
}

std::string extractLHS(const std::string &text) {
    std::regex lhs_regex(R"(([a-zA-Z0-9_._]+)\s*=)");
    std::smatch match;
    if (std::regex_search(text, match, lhs_regex))
        return sanitizeVar(match[1].str());
    return "";
}

std::set<std::string> extractRHS(const std::string &text) {
    std::set<std::string> uses;
    std::regex var_regex(R"(([a-zA-Z_][a-zA-Z0-9_.]*))");
    std::string lhs = extractLHS(text);
    auto words_begin = std::sregex_iterator(text.begin(), text.end(), var_regex);
    auto words_end   = std::sregex_iterator();
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::string var = i->str();
        if (var == lhs || var == "int" || var == "float" || var == "return" || var == "goto" || var == "if" || var == "else") continue;
        if (isdigit(var[0])) continue;
        if (var.find("bb") != std::string::npos) continue;
        uses.insert(var);
    }
    return uses;
}

void applyConstantFolding(FunctionIR &func) {
    std::map<std::string, int> constants;
    bool changed = true;
    std::regex assign_re(R"(([a-zA-Z0-9_._]+)\s*=\s*([0-9]+))");
    std::regex if_re(R"(if\s*\(\s*([a-zA-Z0-9_._]+)\s*(==|!=|>=|<=|>|<)\s*([0-9a-zA-Z_._]+)\s*\))");

    while (changed) {
        changed = false;
        for (auto &block : func.blocks) {
            for (auto &stmt : block.statements) {
                if (stmt.text.find("// Folded") != std::string::npos) continue;
                std::smatch m;
                if (stmt.type == STMT_ASSIGN && std::regex_search(stmt.text, m, assign_re)) {
                    std::string var = sanitizeVar(m[1].str());
                    int val = std::stoi(m[2].str());
                    if (constants.find(var) == constants.end() || constants[var] != val) {
                        constants[var] = val;
                        changed = true;
                    }
                } else if (stmt.type == STMT_COND && std::regex_search(stmt.text, m, if_re)) {
                    std::string var = sanitizeVar(m[1].str());
                    std::string op = m[2].str();
                    std::string rhs = sanitizeVar(m[3].str());
                    int val_rhs = 0;
                    if (constants.count(rhs)) val_rhs = constants[rhs];
                    else if (isdigit(rhs[0])) val_rhs = std::stoi(rhs);
                    else continue;

                    if (constants.count(var)) {
                        int v = constants[var];
                        bool result = false;
                        if (op == "==") result = (v == val_rhs);
                        else if (op == "!=") result = (v != val_rhs);
                        else if (op == ">")  result = (v > val_rhs);
                        else if (op == ">=") result = (v >= val_rhs);
                        else if (op == "<")  result = (v < val_rhs);
                        else if (op == "<=") result = (v <= val_rhs);

                        std::cout << "[DCE Log] SCCP Folding " << (result?"TRUE":"FALSE") << ": " << stmt.text << std::endl;
                        stmt.text = "// Folded: " + stmt.text;
                        stmt.type = STMT_OTHER;
                        
                        // Prune dead successor
                        std::vector<int> gotos;
                        for (int i=0; i<(int)block.statements.size(); ++i)
                            if (block.statements[i].type == STMT_GOTO) gotos.push_back(i);
                        
                        int dead_idx = result ? 1 : 0; // if TRUE, kill false branch (index 1)
                        if (dead_idx < (int)gotos.size()) {
                            int sidx = gotos[dead_idx];
                            std::smatch gm;
                            std::regex gre(R"(goto\s*<bb\s*(\d+)>)");
                            if (std::regex_search(block.statements[sidx].text, gm, gre)) {
                                int target = std::stoi(gm[1].str());
                                block.statements[sidx].text = "// Folded GOTO";
                                block.statements[sidx].type = STMT_OTHER;
                                block.successors.erase(std::remove(block.successors.begin(), block.successors.end(), target), block.successors.end());
                            }
                        }
                        changed = true;
                    }
                }
            }
        }
    }
}

void removeUnreachableBlocks(FunctionIR &func) {
    if (func.blocks.empty()) return;
    std::set<int> reachable;
    std::queue<int> q;
    q.push(func.blocks[0].id);
    reachable.insert(func.blocks[0].id);
    while (!q.empty()) {
        int curr = q.front(); q.pop();
        for (const auto &b : func.blocks) {
            if (b.id == curr) {
                for (int s : b.successors) if (reachable.find(s) == reachable.end()) { reachable.insert(s); q.push(s); }
                break;
            }
        }
    }
    std::set<int> dead_blocks;
    for (auto &b : func.blocks) if (reachable.find(b.id) == reachable.end()) {
        std::cout << "[DCE Log] Removing unreachable Block " << b.id << std::endl;
        for (const auto& stmt : b.statements) {
            std::string lhs = extractLHS(stmt.text);
            if (!lhs.empty()) repair_ssa_uses(func, lhs, "undef");
        }
        b.statements.clear();
        b.successors.clear();
        dead_blocks.insert(b.id);
    }
    
    if (!dead_blocks.empty()) {
        fix_cfg_and_phis(func, dead_blocks);
    }
}

void applyDCE(FunctionIR &func) {
    applyConstantFolding(func);
    
    // Remove statements after terminal (RETURN/GOTO)
    for (auto &b : func.blocks) {
        bool terminal_found = false;
        auto it = b.statements.begin();
        while (it != b.statements.end()) {
            if (terminal_found) {
                std::cout << "[DCE Log] Removing statement after terminal: " << it->text << std::endl;
                it = b.statements.erase(it);
            } else {
                if (it->type == STMT_RETURN || it->type == STMT_GOTO) terminal_found = true;
                ++it;
            }
        }
    }

    removeUnreachableBlocks(func);
    std::set<int> live_stmts;
    std::set<std::string> live_vars;
    auto mark = [&](const Statement &s) {
        if (s.type == STMT_RETURN || s.type == STMT_CALL || s.type == STMT_GOTO || s.type == STMT_COND || hasSideEffect(s)) {
            live_stmts.insert(s.id);
            auto uses = extractRHS(s.text);
            live_vars.insert(uses.begin(), uses.end());
        }
    };
    for (const auto &s : func.preamble) mark(s);
    for (const auto &b : func.blocks) for (const auto &s : b.statements) mark(s);
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto &b : func.blocks) for (auto it = b.statements.rbegin(); it != b.statements.rend(); ++it) {
            if (live_stmts.count(it->id)) continue;
            std::string lhs = extractLHS(it->text);
            if (!lhs.empty() && live_vars.count(lhs)) {
                live_stmts.insert(it->id);
                auto uses = extractRHS(it->text);
                live_vars.insert(uses.begin(), uses.end());
                changed = true;
            }
        }
    }
    auto sweep = [&](std::vector<Statement> &v) {
        v.erase(std::remove_if(v.begin(), v.end(), [&](const Statement &s) {
            if (live_stmts.count(s.id) == 0 && !hasSideEffect(s)) {
                std::cout << "[DCE Log] Removing dead entry: " << s.text << std::endl;
                std::string lhs = extractLHS(s.text);
                if (!lhs.empty()) repair_ssa_uses(func, lhs, "undef");
                return true;
            }
            return false;
        }), v.end());
    };
    sweep(func.preamble);
    for (auto &b : func.blocks) sweep(b.statements);
}


void removeUnusedFunctions(ProgramIR &prog) {
    std::set<std::string> called;
    called.insert("main");

    // Trace calls
    bool changed = true;
    while (changed) {
        changed = false;
        size_t initial_size = called.size();
        for (const auto &func : prog.functions) {
            // Only search in functions that are already known to be "called"
            bool is_reachable = false;
            for (const auto &c : called) {
                if (func.name.find(c) != std::string::npos) {
                    is_reachable = true;
                    break;
                }
            }
            if (!is_reachable) continue;

            for (const auto &block : func.blocks) {
                for (const auto &stmt : block.statements) {
                    if (stmt.type == STMT_CALL) {
                        // Very simple function name extraction
                        std::regex call_re(R"(([a-zA-Z0-9_._]+)\s*\()");
                        std::smatch match;
                        if (std::regex_search(stmt.text, match, call_re)) {
                            std::string fname = match[1].str();
                            if (called.find(fname) == called.end()) {
                                called.insert(fname);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    auto it = prog.functions.begin();
    while (it != prog.functions.end()) {
        bool result = false;
        for (const auto &c : called) {
            if (it->name.find(c) != std::string::npos) {
                result = true;
                break;
            }
        }
        if (!result) {
            std::cout << "[DCE Log] Removing unused function: " << it->name << std::endl;
            it = prog.functions.erase(it);
        } else {
            ++it;
        }
    }
}

void applyGlobalDCE(ProgramIR &prog) {
    removeUnusedFunctions(prog);
    for (auto &f : prog.functions) {
        applyDCE(f);
        validate(f);
    }
}

void applyIntelligentDCE(ProgramIR &prog, const std::map<int, std::string>& dead_reasons) {
    for (auto &f : prog.functions) {
        // structural reachability is still kept as a post-process
        auto sweep = [&](std::vector<Statement> &v) {
            v.erase(std::remove_if(v.begin(), v.end(), [&](const Statement &s) {
                if (dead_reasons.count(s.id)) {
                    std::cout << "[ML DCE Log] " << dead_reasons.at(s.id) << ": " << s.text << std::endl;
                    std::string lhs = extractLHS(s.text);
                    if (!lhs.empty()) repair_ssa_uses(f, lhs, "undef");
                    return true;
                }
                return false;
            }), v.end());
        };
        sweep(f.preamble);
        for (auto &b : f.blocks) sweep(b.statements);
        removeUnreachableBlocks(f);
        validate(f);
    }
    // Final cleanup: remove functions that became empty (except main)
    prog.functions.erase(std::remove_if(prog.functions.begin(), prog.functions.end(),
        [&](const FunctionIR& f) {
            if (f.name.find("main") != std::string::npos) return false;
            bool has_stmts = !f.preamble.empty();
            for (const auto& b : f.blocks) if (!b.statements.empty()) has_stmts = true;
            return !has_stmts;
        }), prog.functions.end());
}
