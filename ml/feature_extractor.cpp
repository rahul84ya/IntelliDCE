#include "ir.h"
#include <iostream>
#include <fstream>
#include <functional>
#include <map>
#include <vector>
#include <set>
#include <string>
#include <queue>
#include <algorithm>

extern bool hasSideEffect(const Statement& stmt);
extern std::string extractLHS(const std::string &text);
extern std::set<std::string> extractRHS(const std::string &text);

// ── Utility: get first stmt id in a block (for branch edges) ────────────────
int get_first_stmt_id(const FunctionIR& func, int block_id, std::set<int>& visited) {
    if (visited.count(block_id)) return -1;
    visited.insert(block_id);
    for (const auto& b : func.blocks) {
        if (b.id == block_id) {
            if (!b.statements.empty()) return b.statements[0].id;
            for (int succ : b.successors) {
                int tid = get_first_stmt_id(func, succ, visited);
                if (tid != -1) return tid;
            }
            return -1;
        }
    }
    return -1;
}

int get_first_stmt_id(const FunctionIR& func, int block_id) {
    std::set<int> visited;
    return get_first_stmt_id(func, block_id, visited);
}

// ── JSON escape ──────────────────────────────────────────────────────────────
std::string escapeJSON(const std::string& input) {
    std::string output;
    for (char c : input) {
        if      (c == '"')  output += "\\\"";
        else if (c == '\\') output += "\\\\";
        else if (c == '\n') output += "\\n";
        else                output += c;
    }
    return output;
}

// ── Opcode embedding ─────────────────────────────────────────────────────────
int getOpcodeEmbedding(StmtType type) {
    switch(type) {
        case STMT_ASSIGN: return 1;
        case STMT_CALL:   return 2;
        case STMT_GOTO:   return 3;
        case STMT_COND:   return 4;
        case STMT_RETURN: return 5;
        default:          return 0;
    }
}

// ── Feature 4: approximate post-dominator depth ──────────────────────────────
// We reverse the CFG and do BFS from exit (last block).
// post_dom_depth[block_id] = BFS depth in reverse CFG.
std::map<int, int> computePostDomDepth(const FunctionIR& func) {
    std::map<int, int> depth;
    if (func.blocks.empty()) return depth;

    // Build reverse adjacency
    std::map<int, std::vector<int>> rev;
    for (const auto& b : func.blocks) {
        rev[b.id]; // ensure entry exists
        for (int s : b.successors) rev[s].push_back(b.id);
    }

    // Find exit blocks (no successors or only the last block)
    std::queue<int> q;
    for (const auto& b : func.blocks) {
        if (b.successors.empty()) {
            q.push(b.id);
            depth[b.id] = 0;
        }
    }
    // Fallback: last block is exit
    if (q.empty() && !func.blocks.empty()) {
        int last_id = func.blocks.back().id;
        q.push(last_id);
        depth[last_id] = 0;
    }

    while (!q.empty()) {
        int curr = q.front(); q.pop();
        for (int pred : rev[curr]) {
            if (depth.find(pred) == depth.end()) {
                depth[pred] = depth[curr] + 1;
                q.push(pred);
            }
        }
    }
    return depth;
}

// ── Feature 6: approximate loop depth via back-edge detection ────────────────
// A back edge exists when a successor appears earlier in DFS discovery order.
std::map<int, int> computeLoopDepth(const FunctionIR& func) {
    std::map<int, int> loop_depth;
    if (func.blocks.empty()) return loop_depth;
    for (const auto& b : func.blocks) loop_depth[b.id] = 0;

    std::map<int, int> disc_order;
    int timer = 0;
    std::function<void(int)> dfs = [&](int bid) {
        if (disc_order.count(bid)) return;
        disc_order[bid] = timer++;
        for (const auto& b : func.blocks) {
            if (b.id == bid) {
                for (int succ : b.successors) {
                    if (!disc_order.count(succ)) { dfs(succ); }
                    else if (disc_order[succ] <= disc_order[bid]) {
                        // Back edge — increment loop depth for all nodes in the cycle
                        loop_depth[bid]++;
                        loop_depth[succ]++;
                    }
                }
                break;
            }
        }
    };
    if (!func.blocks.empty()) dfs(func.blocks[0].id);
    return loop_depth;
}

// ── Feature 7: is_branch_target (block has 2+ predecessors) ──────────────────
std::set<int> computeBranchTargets(const FunctionIR& func) {
    std::map<int, int> pred_count;
    for (const auto& b : func.blocks) {
        for (int s : b.successors) pred_count[s]++;
    }
    std::set<int> result;
    for (const auto& [bid, cnt] : pred_count) {
        if (cnt >= 2) result.insert(bid);
    }
    return result;
}

// ── Main export function ──────────────────────────────────────────────────────
/*
 * Feature vector per node (10 dimensions):
 *   [0] opcode          (int 0-5)
 *   [1] side_effect     (0/1)
 *   [2] after_terminal  (0/1)
 *   [3] use_count       (int)
 *   [4] post_dom_depth  (int, approx)
 *   [5] is_phi          (0/1)
 *   [6] loop_depth      (int, approx)
 *   [7] is_branch_target(0/1)
 *   [8] is_func_call    (0/1)
 *   [9] is_io           (0/1)
 *
 * Edge types:
 *   "CFG"         — sequential within a block
 *   "DFG"         — def-use dependency
 *   "CFG_BRANCH"  — block-to-block control flow
 *   "PDG"         — program dependence (side-effecting → dominated stmts)
 */
void exportIRFeaturesToJSON(const ProgramIR& prog, const std::string& out_path) {
    std::ofstream out(out_path);
    out << "{\n  \"functions\": [\n";

    for (size_t f_idx = 0; f_idx < prog.functions.size(); ++f_idx) {
        const auto& func = prog.functions[f_idx];
        out << "    {\n";
        out << "      \"name\": \"" << escapeJSON(func.name) << "\",\n";
        out << "      \"nodes\": [\n";

        // ── Pre-compute structural features ──────────────────────────────────
        std::map<std::string, std::vector<int>> def_chains;
        std::map<std::string, int>              use_counts;
        auto post_dom = computePostDomDepth(func);
        auto loop_dep = computeLoopDepth(func);
        auto br_tgts  = computeBranchTargets(func);

        for (const auto& block : func.blocks) {
            for (const auto& stmt : block.statements) {
                auto uses = extractRHS(stmt.text);
                for (const auto& u : uses) use_counts[u]++;
            }
        }

        // ── Emit nodes ───────────────────────────────────────────────────────
        bool first_node = true;
        for (const auto& block : func.blocks) {
            // Detect after_terminal within this block
            bool after_terminal = false;

            // is_phi: check if statement contains "PHI"
            // is_branch_target: block is in br_tgts
            int  pd_depth  = post_dom.count(block.id) ? post_dom.at(block.id) : 0;
            int  lp_depth  = loop_dep.count(block.id) ? loop_dep.at(block.id) : 0;
            int  is_bt     = br_tgts.count(block.id) ? 1 : 0;

            for (const auto& stmt : block.statements) {
                if (!first_node) out << ",\n";
                first_node = false;

                int  opcode      = getOpcodeEmbedding(stmt.type);
                bool side_effect = hasSideEffect(stmt);
                bool is_phi      = (stmt.text.find("PHI") != std::string::npos ||
                                    stmt.text.find("phi") != std::string::npos);
                bool is_func_call = (stmt.type == STMT_CALL);
                bool is_io = (stmt.text.find("printf") != std::string::npos ||
                              stmt.text.find("cout") != std::string::npos ||
                              stmt.text.find("scanf") != std::string::npos ||
                              stmt.text.find("std::ostream") != std::string::npos ||
                              stmt.text.find("puts") != std::string::npos);

                std::string lhs     = extractLHS(stmt.text);
                auto        rhs_set = extractRHS(stmt.text);
                std::vector<std::string> rhs(rhs_set.begin(), rhs_set.end());
                int use_c = lhs.empty() ? 0 : use_counts[lhs];

                if (!lhs.empty()) def_chains[lhs].push_back(stmt.id);

                out << "        {\n";
                out << "          \"id\": "       << stmt.id    << ",\n";
                out << "          \"block_id\": " << block.id   << ",\n";
                out << "          \"text\": \""   << escapeJSON(stmt.text) << "\",\n";
                out << "          \"lhs\": \""    << escapeJSON(lhs)       << "\",\n";
                out << "          \"rhs\": [";
                for (size_t i = 0; i < rhs.size(); ++i)
                    out << "\"" << escapeJSON(rhs[i]) << "\""
                        << (i < rhs.size() - 1 ? ", " : "");
                out << "],\n";

                // 10-dimensional feature vector
                out << "          \"features\": ["
                    << opcode                   << ", "
                    << (side_effect  ? 1 : 0)  << ", "
                    << (after_terminal ? 1 : 0)<< ", "
                    << use_c                    << ", "
                    << pd_depth                 << ", "
                    << (is_phi ? 1 : 0)        << ", "
                    << lp_depth                 << ", "
                    << is_bt                    << ", "
                    << (is_func_call ? 1 : 0)  << ", "
                    << (is_io ? 1 : 0)         << "]\n";
                out << "        }";

                // Update after_terminal for next iteration
                if (stmt.type == STMT_RETURN || stmt.type == STMT_GOTO)
                    after_terminal = true;
            }
        }

        out << "\n      ],\n";

        // ── Emit edges ───────────────────────────────────────────────────────
        out << "      \"edges\": [\n";
        bool first_edge = true;

        // Collect side-effecting statement IDs for PDG edges
        std::set<int> side_effect_stmts;

        for (const auto& block : func.blocks) {
            int last_stmt_id = -1;
            for (const auto& stmt : block.statements) {
                if (last_stmt_id != -1) {
                    if (!first_edge) out << ",\n";
                    out << "        {\"source\": " << last_stmt_id
                        << ", \"target\": "        << stmt.id
                        << ", \"type\": \"CFG\"}";
                    first_edge = false;
                }
                last_stmt_id = stmt.id;

                if (hasSideEffect(stmt)) side_effect_stmts.insert(stmt.id);

                // DFG: def → use
                auto rhs_vars = extractRHS(stmt.text);
                for (const auto& var : rhs_vars) {
                    if (def_chains.count(var)) {
                        for (int def_id : def_chains[var]) {
                            if (!first_edge) out << ",\n";
                            out << "        {\"source\": " << def_id
                                << ", \"target\": "        << stmt.id
                                << ", \"type\": \"DFG\"}";
                            first_edge = false;
                        }
                    }
                }
            }

            // CFG_BRANCH: last stmt → first stmt of successor block
            if (last_stmt_id != -1) {
                for (int succ_id : block.successors) {
                    int tgt = get_first_stmt_id(func, succ_id);
                    if (tgt != -1) {
                        if (!first_edge) out << ",\n";
                        out << "        {\"source\": " << last_stmt_id
                            << ", \"target\": "        << tgt
                            << ", \"type\": \"CFG_BRANCH\"}";
                        first_edge = false;
                    }
                }
            }
        }

        // PDG edges: each side-effecting stmt → every stmt in the same block
        // (conservative control dependence approximation)
        for (const auto& block : func.blocks) {
            for (int se_id : side_effect_stmts) {
                // Check if se_id is in this block
                bool found = false;
                for (const auto& s : block.statements)
                    if (s.id == se_id) { found = true; break; }
                if (!found) continue;

                for (const auto& stmt : block.statements) {
                    if (stmt.id == se_id) continue;
                    if (!first_edge) out << ",\n";
                    out << "        {\"source\": " << se_id
                        << ", \"target\": "        << stmt.id
                        << ", \"type\": \"PDG\"}";
                    first_edge = false;
                }
            }
        }

        out << "\n      ]\n    }";
        if (f_idx < prog.functions.size() - 1) out << ",";
        out << "\n";
    }

    out << "  ]\n}\n";
    out.close();
    std::cout << "[ML Pipeline] Exported IR Graph features (10-d + PDG) → " << out_path << "\n";
}
