#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <map>
#include <cstdlib>
#include "ir.h"

namespace fs = std::filesystem;

extern int yyparse();
void applyGlobalDCE(ProgramIR& prog);
void exportIRFeaturesToJSON(const ProgramIR& prog, const std::string& out_path);
void applyIntelligentDCE(ProgramIR& prog, const std::map<int, std::string>& dead_reasons);

void export_to_ssa(const ProgramIR& prog, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) {
        std::cerr << "[Error] Cannot open file for writing: " << filepath << "\n";
        return;
    }
    for (const auto& func : prog.functions) {
        out << func.name << "\n";
        for (const auto& stmt : func.preamble) {
            out << "  " << stmt.text << "\n";
        }
        for (const auto& block : func.blocks) {
            out << "<bb " << block.id << ">:\n";
            for (const auto& stmt : block.statements) {
                if (stmt.text.find("// Folded") != std::string::npos) continue;
                out << "  " << stmt.text << "\n";
            }
        }
        out << "\n";
    }
}

void export_to_dot(const ProgramIR& prog, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) {
        std::cerr << "[Error] Cannot open file for writing: " << filepath << "\n";
        return;
    }

    out << "digraph G {\n";
    out << "  node [shape=box, fontname=\"Courier\", style=filled, fillcolor=white];\n";
    out << "  compound=true;\n";

    int func_counter = 0;
    for (const auto& func : prog.functions) {
        func_counter++;
        std::string cluster_id = "cluster_" + std::to_string(func_counter);

        out << "  subgraph \"" << cluster_id << "\" {\n";
        out << "    label = \"" << func.name << "\";\n";
        out << "    style = dashed; color = blue;\n";

        for (const auto& block : func.blocks) {
            std::string node_id = "node_" + std::to_string(func_counter) + "_" + std::to_string(block.id);
            out << "    " << node_id << " [label=\"BB " << block.id << "\\n";
            for (const auto& stmt : block.statements) {
                std::string clean = stmt.text;
                size_t p = 0;
                while ((p = clean.find('"', p)) != std::string::npos) { clean.replace(p, 1, "\\\""); p += 2; }
                out << clean << "\\n";
            }
            out << "\"];\n";

            for (int succ : block.successors) {
                std::string target_id = "node_" + std::to_string(func_counter) + "_" + std::to_string(succ);
                out << "    " << node_id << " -> " << target_id << ";\n";
            }
        }
        out << "  }\n";
    }
    out << "}\n";
}

int main(int argc, char** argv) {
    bool ml_extract = false;
    bool ml_dce = false;
    double ml_threshold = 0.6;   // confidence threshold for ML dead-code removal
    std::string projectName = "analysis_report";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--ml-extract") ml_extract = true;
        else if (arg == "--ml-dce") ml_dce = true;
        else if (arg.rfind("--ml-threshold", 0) == 0) {
            // Accept --ml-threshold=0.7 or --ml-threshold 0.7
            if (arg.find('=') != std::string::npos)
                ml_threshold = std::stod(arg.substr(arg.find('=') + 1));
            else if (i + 1 < argc)
                ml_threshold = std::stod(argv[++i]);
        }
        else if (arg.rfind("--", 0) != 0) projectName = arg;
    }

    if (yyparse() == 0) {
        if (ml_extract) {
            if (!fs::exists(projectName)) fs::create_directory(projectName);
            exportIRFeaturesToJSON(program, projectName + "/ir_graph_features.json");
        }

        if (ml_dce && !ml_extract) {
            std::cout << "[ML Pipeline] Starting ML Inference DCE Pass (threshold=" << ml_threshold << ")...\n";
            if (!fs::exists(projectName)) fs::create_directory(projectName);
            std::string tmp_graph = projectName + "/tmp_ir_graph.json";
            std::string tmp_out   = projectName + "/tmp_ml_preds.json";

            exportIRFeaturesToJSON(program, tmp_graph);

            // Portable Python detection: use INTELLIDCE_PYTHON env var or default to 'python3'
            std::string python_cmd = "python3";
            const char* env_python = std::getenv("INTELLIDCE_PYTHON");
            if (env_python && std::string(env_python).size() > 0) python_cmd = env_python;

            std::string ml_log = projectName + "/ml_stderr.log";

            std::string cmd =
                python_cmd + " ml/inference.py "
                + tmp_graph
                + " ml_data/dce_model.pt"
                + " --threshold " + std::to_string(ml_threshold)
                + " > " + tmp_out + " 2>" + ml_log;
            int ret = std::system(cmd.c_str());

            if (ret != 0) {
                std::cerr << "[ML Error] Inference script failed (exit " << ret << "). Check " << ml_log << "\n";
                std::cerr << "[ML Fallback] Running heuristic pass instead.\n";
                // Re-run without model (heuristic path inside inference.py)
                std::string fb_cmd =
                    python_cmd + " ml/inference.py "
                    + tmp_graph
                    + " /dev/null"
                    + " --threshold " + std::to_string(ml_threshold)
                    + " > " + tmp_out + " 2>" + ml_log;
                ret = std::system(fb_cmd.c_str());
            }

            if (ret == 0) {
                std::ifstream ifs(tmp_out);
                std::string content((std::istreambuf_iterator<char>(ifs)),
                                    (std::istreambuf_iterator<char>()));
                std::map<int, std::string> dead_map;

                // ── Parse dead_items ────────────────────────────────────────
                // Format: {"id": N, "reason": "...", "confidence": F,
                //          "source": "...", "top_influencers": [...]}
                size_t pos = 0;
                while ((pos = content.find("\"id\":", pos)) != std::string::npos) {
                    pos += 5;
                    while (pos < content.size() && !isdigit(content[pos])) pos++;
                    if (pos >= content.size()) break;
                    size_t end_id = 0;
                    int id = std::stoi(content.substr(pos), &end_id);
                    pos += end_id;

                    // reason
                    std::string reason = "dead code (ml)";
                    size_t r_pos = content.find("\"reason\":", pos);
                    if (r_pos != std::string::npos && r_pos < pos + 200) {
                        r_pos = content.find('"', r_pos + 9);
                        if (r_pos != std::string::npos) {
                            ++r_pos;
                            size_t r_end = content.find('"', r_pos);
                            if (r_end != std::string::npos)
                                reason = content.substr(r_pos, r_end - r_pos);
                        }
                    }

                    // confidence (for logging)
                    double conf = 1.0;
                    size_t c_pos = content.find("\"confidence\":", pos);
                    if (c_pos != std::string::npos && c_pos < pos + 300) {
                        c_pos += 14;
                        while (c_pos < content.size() &&
                               !isdigit(content[c_pos]) && content[c_pos] != '.') ++c_pos;
                        try { conf = std::stod(content.substr(c_pos)); } catch (...) {}
                    }

                    // source
                    std::string src = "gnn";
                    size_t s_pos = content.find("\"source\":", pos);
                    if (s_pos != std::string::npos && s_pos < pos + 400) {
                        s_pos = content.find('"', s_pos + 9);
                        if (s_pos != std::string::npos) {
                            ++s_pos;
                            size_t s_end = content.find('"', s_pos);
                            if (s_end != std::string::npos)
                                src = content.substr(s_pos, s_end - s_pos);
                        }
                    }

                    std::string tag = (src == "gnn") ? "[ML GNN]" :
                                      (src == "heuristic") ? "[Heuristic]" : "[Fallback]";
                    std::cout << tag << " conf=" << conf << " " << reason
                              << " (id=" << id << ")\n";
                    dead_map[id] = reason + " [" + src + " conf=" + std::to_string(conf) + "]";
                }

                // ── Parse uncertainty_nodes (deferred — skip removal) ───────
                size_t u_pos = content.find("\"uncertainty_nodes\":");
                if (u_pos != std::string::npos) {
                    u_pos = content.find('[', u_pos);
                    size_t u_end = (u_pos != std::string::npos) ? content.find(']', u_pos) : std::string::npos;
                    if (u_pos != std::string::npos && u_end != std::string::npos) {
                        std::string u_seg = content.substr(u_pos + 1, u_end - u_pos - 1);
                        // Extract numbers
                        size_t up = 0;
                        while (up < u_seg.size()) {
                            while (up < u_seg.size() && !isdigit(u_seg[up])) ++up;
                            if (up >= u_seg.size()) break;
                            size_t ue = 0;
                            int uid = std::stoi(u_seg.substr(up), &ue);
                            up += ue;
                            std::cout << "[ML UNCERTAIN] Node " << uid
                                      << " deferred (confidence 0.50–" << ml_threshold << ")\n";
                        }
                    }
                }

                size_t p_pos = content.find("\"node_probabilities\":");
                if (p_pos != std::string::npos) {
                    p_pos = content.find('[', p_pos);
                    size_t p_end = (p_pos != std::string::npos) ? content.find(']', p_pos) : std::string::npos;
                    if (p_pos != std::string::npos && p_end != std::string::npos) {
                        std::string p_seg = content.substr(p_pos + 1, p_end - p_pos - 1);
                        size_t pp = 0;
                        while ((pp = p_seg.find("\"nodeID\":", pp)) != std::string::npos) {
                            pp += 9;
                            while (pp < p_seg.size() && !isdigit(p_seg[pp])) pp++;
                            if (pp >= p_seg.size()) break;
                            size_t pe = 0;
                            int pid = std::stoi(p_seg.substr(pp), &pe);
                            pp += pe;

                            double pconf = 0.0;
                            size_t cpos = p_seg.find("\"prob\":", pp);
                            if (cpos != std::string::npos) {
                                cpos += 7;
                                while (cpos < p_seg.size() && !isdigit(p_seg[cpos]) && p_seg[cpos] != '.') cpos++;
                                try { pconf = std::stod(p_seg.substr(cpos)); } catch (...) {}
                            }
                            std::cout << "[ML PROBABILITY] Node id=" << pid << " calculated as " << pconf << "\n";
                        }
                    }
                }

                applyIntelligentDCE(program, dead_map);
                std::cout << "[ML Pipeline] Inference complete. "
                          << dead_map.size() << " dead instructions removed.\n";
            } else {
                std::cerr << "[ML Error] Both ML and fallback passes failed.\n";
            }
        } else {
            applyGlobalDCE(program);
        }

        if (ml_extract) {
            exportIRFeaturesToJSON(program, projectName + "/ir_graph_optimized.json");
            return 0;
        }

        if (!fs::exists(projectName)) {
            fs::create_directory(projectName);
        }

        std::ofstream report(projectName + "/summary.txt");
        report << "GIMPLE SSA ANALYSIS REPORT (OPTIMIZED)\n" << std::string(35, '=') << "\n";
        report << "Final number of reachable functions: " << program.functions.size() << "\n\n";

        for (const auto& func : program.functions) {
            report << "Function: " << func.name << "\n";
            report << "  Preamble: " << func.preamble.size() << " declarations remaining\n";
            for (const auto& block : func.blocks) {
                report << "    Block " << block.id << " (" << block.statements.size() << " live stmts)\n";
                report << "      Successors: ";
                for (int s : block.successors) report << s << " ";
                report << "\n";
            }
            report << "\n";
        }
        report.close();

        export_to_dot(program, projectName + "/graph.dot");
        export_to_ssa(program, projectName + "/optimized.ssa");

        std::cout << "Analysis complete. Intermediate logs generated." << std::endl;
        std::cout << "Files generated in folder: ./" << projectName << std::endl;
        std::cout << "To generate image, run: dot -Tpng " << projectName << "/graph.dot -o " << projectName << "/graph.png" << std::endl;

    } else {
        std::cerr << "Parsing failed." << std::endl;
        return 1;
    }
    return 0;
}
