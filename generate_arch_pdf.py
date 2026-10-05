import matplotlib.pyplot as plt
import matplotlib.patches as patches

fig = plt.figure(figsize=(11, 8.5), dpi=150)
ax = fig.add_subplot(111)
ax.axis('off')

# Title Banner
plt.text(0.5, 0.96, "INTELLIDCE: SYSTEM ARCHITECTURE SPECIFICATION", 
         ha='center', va='center', fontsize=15, fontweight='bold', color='#0f172a')
plt.text(0.5, 0.93, "Mid-Evaluation Architectural Evolution: Classical SSA Baseline vs. Proposed AI-Agentic Framework", 
         ha='center', va='center', fontsize=9, color='#475569', style='italic')

# Helper function to draw rounded boxes
def draw_card(ax, x, y, w, h, title, subtitle, items, bg_color, border_color, title_color='#0f172a'):
    rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.015,rounding_size=0.02",
                                  facecolor=bg_color, edgecolor=border_color, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(x + 0.02, y + h - 0.04, title, fontsize=10, fontweight='bold', color=title_color)
    if subtitle:
        ax.text(x + 0.02, y + h - 0.07, subtitle, fontsize=7.5, color='#64748b', style='italic')
    
    start_y = y + h - 0.11 if subtitle else y + h - 0.08
    for i, item in enumerate(items):
        ax.text(x + 0.025, start_y - (i * 0.038), f"• {item}", fontsize=7.5, color='#334155')

# Draw Separator line
line = patches.ConnectionPatch((0.5, 0.05), (0.5, 0.90), "data", "data", 
                              arrowstyle="-", linestyle="--", color="#cbd5e1", linewidth=1.5)
ax.add_artist(line)

# Left Column: EXISTING ARCHITECTURE
ax.text(0.24, 0.88, "SECTION A: EXISTING BASELINE ARCHITECTURE", ha='center', fontsize=11, fontweight='bold', color='#1e293b')
ax.text(0.24, 0.86, "(Traditional SSA & Heuristic DCE Pipeline)", ha='center', fontsize=8, color='#64748b')

draw_card(ax, 0.04, 0.69, 0.40, 0.15, 
          "1. Front-End Ingestion & SSA Dump", 
          "GCC Intermediate Dump Layer",
          ["GCC -O0 -fdump-tree-ssa compilation", 
           "Extracts raw GIMPLE 3-address instructions", 
           "Basic Block (<bb 2>) discovery"],
          "#f8fafc", "#94a3b8")

draw_card(ax, 0.04, 0.51, 0.40, 0.15, 
          "2. Lexical & Parsing Engine", 
          "src/lexer.l & src/parser.y",
          ["Flex Tokenizer for SSA identifiers and opcodes", 
           "Bison LALR Context-Free Grammar parser", 
           "Constructs in-memory ProgramIR & FunctionIR"],
          "#f8fafc", "#94a3b8")

draw_card(ax, 0.04, 0.33, 0.40, 0.15, 
          "3. Classical Optimization Core", 
          "src/analysis.cpp (Heuristic Passes)",
          ["SCCP (Sparse Conditional Constant Propagation)", 
           "Reachability Analysis (BFS/DFS block culling)", 
           "Local Dead Store Elimination (Def-Use Chains)", 
           "Deterministic CFG Edge & PHI Repair"],
          "#f8fafc", "#94a3b8")

draw_card(ax, 0.04, 0.15, 0.40, 0.15, 
          "4. Output Emission & Dot Graph", 
          "Terminal Pass & Visualization",
          ["Generates optimized.ssa binary representation", 
           "Exports graph.dot for Graphviz rendering", 
           "summary.txt emission with statement counts"],
          "#f8fafc", "#94a3b8")

# Right Column: PROPOSED ARCHITECTURE
ax.text(0.74, 0.88, "SECTION B: PROPOSED ENHANCED ARCHITECTURE", ha='center', fontsize=11, fontweight='bold', color='#0284c7')
ax.text(0.74, 0.86, "(Modules 1, 3, 4: GNN + Agentic AI + Security Triage)", ha='center', fontsize=8, color='#0284c7')

draw_card(ax, 0.54, 0.69, 0.42, 0.15, 
          "1. 74-D Neural Graph Representation", 
          "ml/feature_extractor.cpp + MiniLM Embeddings",
          ["10 Structural Features (loop depth, post-dom, def-use)", 
           "64-D Semantic Embeddings via MiniLM-L6-v2", 
           "Hybrid SAGEConv + GATConv Multi-Head Attention", 
           "Attention weights provide intrinsic interpretability"],
          "#f0fdf4", "#86efac", "#166534")

draw_card(ax, 0.54, 0.51, 0.42, 0.15, 
          "2. Safety Veto & Invariant Engine", 
          "Asymmetric Safety Verification Layer",
          ["Strict side-effect auditor (I/O, system, volatile)", 
           "Vetoes neural drops if memory safety is at risk", 
           "Semantic equivalence preservation guarantee"],
          "#eff6ff", "#93c5fd", "#1e40af")

draw_card(ax, 0.54, 0.33, 0.42, 0.15, 
          "3. Vulnerability Pattern Scanner (Mod 2/4)", 
          "Security Triage & CWE Mapping",
          ["CWE-570/571: Invariant Control Gates (Always-False)", 
           "CWE-561: Dead Stores to Passwords/Auth Buffers", 
           "CWE-670: Dormant Dangerous Library Primitives", 
           "Automated CWE risk score & remediation advice"],
          "#fef2f2", "#fca5a5", "#991b1b")

draw_card(ax, 0.54, 0.11, 0.42, 0.19, 
          "4. Vitality Scorecard & AI Agent (Mod 1/3)", 
          "Interactive Dashboard & Agentic Assistant",
          ["Code Health Score (0-100) & Quality Badges", 
           "Cyclomatic complexity & dead code density metrics", 
           "AI DCE Explainer with semantic root-cause analysis", 
           "Automated C++ refactoring fix recommendation", 
           "Interactive AI Agent Dialogue for compiler queries"],
          "#faf5ff", "#d8b4fe", "#6b21a8")

# Bottom Footer
plt.text(0.5, 0.03, "Project: Intelligent Dead Code Elimination Tool | Stage: Mid-Evaluation (30% Scope Completed)", 
         ha='center', va='center', fontsize=8, color='#64748b')

plt.tight_layout()
plt.savefig("IntelliDCE_Architecture_Specification.pdf", format="pdf", bbox_inches='tight')
plt.savefig("IntelliDCE_Architecture_Specification.png", format="png", bbox_inches='tight', dpi=200)
print("Generated PDF and PNG successfully!")
