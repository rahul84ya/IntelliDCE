import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyArrowPatch
import os

# Create figure with high-definition landscape dimensions
fig = plt.figure(figsize=(18, 11), dpi=150)
ax = fig.add_subplot(111)
ax.axis('off')
ax.set_xlim(0, 1.0)
ax.set_ylim(0, 1.0)

# Colors
C_DARK = "#0f172a"
C_SLATE = "#334155"
C_MUTED = "#64748b"
C_BORDER_BASE = "#94a3b8"
C_BG_BASE = "#f8fafc"

C_ACCENT_BLUE = "#0284c7"
C_ACCENT_GREEN = "#16a34a"
C_ACCENT_AMBER = "#d97706"
C_ACCENT_PURPLE = "#7c3aed"
C_ACCENT_RED = "#dc2626"
C_ACCENT_TEAL = "#0d9488"

# Title Header
plt.text(0.5, 0.975, "INTELLIDCE: END-TO-END SYSTEM ARCHITECTURE SPECIFICATION", 
         ha='center', va='center', fontsize=16, fontweight='bold', color=C_DARK)
plt.text(0.5, 0.952, "Comparative Architectural Blueprint: Classical SSA Baseline vs. Proposed 7-Module Agentic & Secure Pipeline", 
         ha='center', va='center', fontsize=9.5, color='#475569', style='italic')

# Header Separator
ax.plot([0.02, 0.98], [0.938, 0.938], color="#cbd5e1", lw=1.2)

# Global Vertical Column Separator
ax.plot([0.275, 0.275], [0.035, 0.925], color="#cbd5e1", lw=1.5, linestyle="--")

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def draw_box(ax, x, y, w, h, title, subtitle, bullets, bg_color, border_color, title_color=C_DARK, tag=None, tag_bg="#e2e8f0", tag_fg="#1e293b"):
    rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.015",
                                  facecolor=bg_color, edgecolor=border_color, linewidth=1.4, zorder=2)
    ax.add_patch(rect)
    
    # Tag Badge (e.g. Module 1)
    if tag:
        tag_w = len(tag) * 0.0072 + 0.02
        tag_rect = patches.FancyBboxPatch((x + w - tag_w - 0.012, y + h - 0.028), tag_w, 0.022, 
                                          boxstyle="round,pad=0.004,rounding_size=0.006",
                                          facecolor=tag_bg, edgecolor=border_color, linewidth=0.8, zorder=3)
        ax.add_patch(tag_rect)
        ax.text(x + w - (tag_w/2) - 0.012, y + h - 0.017, tag, fontsize=6.8, fontweight='bold', 
                color=tag_fg, ha='center', va='center', zorder=4)

    # Title
    ax.text(x + 0.014, y + h - 0.025, title, fontsize=8.8, fontweight='bold', color=title_color, zorder=3)
    
    # Subtitle
    curr_y = y + h - 0.045
    if subtitle:
        ax.text(x + 0.014, curr_y, subtitle, fontsize=7.0, color=C_MUTED, style='italic', zorder=3)
        curr_y -= 0.022
    else:
        curr_y -= 0.008

    # Bullets
    for b in bullets:
        ax.text(x + 0.015, curr_y, f"• {b}", fontsize=6.7, color=C_SLATE, zorder=3)
        curr_y -= 0.020

def draw_arrow(ax, p1, p2, color="#64748b", style="->", rad=0.0, lw=1.3, ls="-", label=None, label_pos=(0,0)):
    arrow = FancyArrowPatch(p1, p2, arrowstyle=style, connectionstyle=f"arc3,rad={rad}",
                            color=color, linewidth=lw, linestyle=ls, zorder=5, mutation_scale=11)
    ax.add_patch(arrow)
    if label:
        ax.text(label_pos[0], label_pos[1], label, fontsize=6.5, fontweight='bold', color=color, 
                ha='center', va='center', backgroundcolor='#ffffff', zorder=6)

# ==========================================
# LEFT COLUMN: EXISTING ARCHITECTURE
# ==========================================
ax.text(0.145, 0.915, "EXISTING BASELINE ARCHITECTURE", ha='center', fontsize=11, fontweight='bold', color='#1e293b')
ax.text(0.145, 0.898, "(Classical Heuristic SSA Optimization Pipeline)", ha='center', fontsize=7.5, color=C_MUTED)

# Node E1: Source Code
draw_box(ax, 0.025, 0.815, 0.235, 0.065,
         "1. C/C++ Source Input", "Raw User Program",
         ["Single compilation unit (.cpp / .c)", "No pre-execution security verification"],
         C_BG_BASE, C_BORDER_BASE)

# Node E2: GCC Ingestion
draw_box(ax, 0.025, 0.705, 0.235, 0.080,
         "2. GCC Front-End & GIMPLE SSA", "GCC -O0 -fdump-tree-ssa Ingestion",
         ["Translates AST to 3-address GIMPLE code", "Exposes explicit phi-nodes (Φ) and blocks", "Dumps raw static text files (.ssa)"],
         C_BG_BASE, C_BORDER_BASE)

# Node E3: Lexer & Parser
draw_box(ax, 0.025, 0.590, 0.235, 0.085,
         "3. Lexer & Parser Layer", "src/lexer.l (Flex) & src/parser.y (Bison)",
         ["Flex scans tokens (opcodes, variables)", "Bison LALR grammar validates syntax", "Builds in-memory ProgramIR & FunctionIR"],
         C_BG_BASE, C_BORDER_BASE)

# Node E4: Heuristic Engine
draw_box(ax, 0.025, 0.450, 0.235, 0.110,
         "4. Classical Heuristic DCE Engine", "src/analysis.cpp (Heuristic Passes)",
         ["Sparse Conditional Constant Propagation", "BFS/DFS unreachable block pruning", "Local dead store elimination (Def-Use)", "Basic phi-node & control edge cleanup"],
         "#fef2f2", "#fca5a5", title_color="#991b1b")

# Node E5: Output Emission
draw_box(ax, 0.025, 0.335, 0.235, 0.085,
         "5. Static File Emission", "Direct Disk Output",
         ["Emits optimized.ssa text file", "Generates graph.dot for Graphviz", "Produces summary.txt with basic counts"],
         C_BG_BASE, C_BORDER_BASE)

# Node E6: Host GUI
draw_box(ax, 0.025, 0.230, 0.235, 0.075,
         "6. Direct Host Web UI", "Express + Static HTML/D3.js",
         ["Direct local host execution (unsandboxed)", "D3.js interactive CFG visualization", "Shows raw before/after code panes"],
         C_BG_BASE, C_BORDER_BASE)

# Existing Architecture Arrows
draw_arrow(ax, (0.142, 0.815), (0.142, 0.785), color=C_MUTED)
draw_arrow(ax, (0.142, 0.705), (0.142, 0.675), color=C_MUTED)
draw_arrow(ax, (0.142, 0.590), (0.142, 0.560), color=C_MUTED)
draw_arrow(ax, (0.142, 0.450), (0.142, 0.420), color=C_MUTED)
draw_arrow(ax, (0.142, 0.335), (0.142, 0.305), color=C_MUTED)

# Existing Architecture Limitations Box
draw_box(ax, 0.025, 0.040, 0.235, 0.160,
         "CRITICAL SYSTEM LIMITATIONS", "Architectural Deficiencies Identified:",
         ["Strict heuristic limits: misses semantic dead code", 
          "Zero security awareness: sensitive dead stores ignored", 
          "Black-box elimination: no developer explanation", 
          "Unsandboxed execution: host vulnerable to exploits", 
          "No verification: semantic breakage undetected", 
          "No feedback loop: static model never improves"],
         "#fff1f2", "#fda4af", title_color="#be123c")


# ==========================================
# RIGHT COLUMN: PROPOSED 7-MODULE ARCHITECTURE
# ==========================================
ax.text(0.640, 0.915, "PROPOSED ENHANCED SYSTEM ARCHITECTURE (FULL 7-MODULE VISION)", ha='center', fontsize=11.5, fontweight='bold', color=C_ACCENT_BLUE)
ax.text(0.640, 0.898, "(End-to-End Secure, Agentic AI, Neural Optimization & Verification Framework)", ha='center', fontsize=7.8, color='#0369a1')

# ------------------------------------------
# LAYER 1: Ingestion & Security Pre-Scan
# ------------------------------------------
# Box P1: Source Input
draw_box(ax, 0.295, 0.815, 0.170, 0.065,
         "Source Code (C/C++)", "User Input Buffer",
         ["Pasted source or uploaded files", "Direct multi-module entrypoint"],
         "#f0fdf4", "#86efac", title_color="#15803d")

# Box P2 [Mod 2]: Vulnerability Scanner
draw_box(ax, 0.495, 0.800, 0.225, 0.080,
         "Vulnerability Pattern Scanner", "Regex & AST Pattern Matching Engine",
         ["CWE-561: Dead memory stores to credentials",
          "CWE-570/571: Invariant always-false control gates",
          "CWE-670: Dormant hazardous APIs (system, strcpy)",
          "CWE-252: Unchecked return value vulnerabilities"],
         "#fef2f2", "#fca5a5", title_color="#991b1b",
         tag="Module 2", tag_bg="#fee2e2", tag_fg="#991b1b")

# Box P3: GCC + Lexer/Parser Engine
draw_box(ax, 0.745, 0.800, 0.230, 0.080,
         "SSA Extraction & Lexer/Parser", "GCC GIMPLE + Flex/Bison Pipeline",
         ["GCC generates explicit SSA 3-address code",
          "Flex tokenizer & Bison LALR grammar",
          "Constructs enriched CFG & Def-Use call chains"],
         C_BG_BASE, C_BORDER_BASE)

# Connect Layer 1
draw_arrow(ax, (0.465, 0.845), (0.495, 0.845), color=C_ACCENT_RED, label="Pre-Scan", label_pos=(0.480, 0.855))
draw_arrow(ax, (0.380, 0.815), (0.380, 0.760), color=C_ACCENT_GREEN)
draw_arrow(ax, (0.380, 0.760), (0.745, 0.835), color=C_MUTED, rad=-0.15)
draw_arrow(ax, (0.605, 0.800), (0.605, 0.740), color=C_ACCENT_RED) # Sec data down to Health Score

# ------------------------------------------
# LAYER 2: 74-D Graph Neural Representation
# ------------------------------------------
draw_box(ax, 0.350, 0.655, 0.270, 0.090,
         "74-D Neural Graph Representation", "Hybrid Structural & Semantic Embedding",
         ["10 Structural Features: loop depth, post-dom, def-use span",
          "64-D Semantic Embeddings via MiniLM-L6-v2 transformer",
          "Constructs PyTorch Geometric HeteroData Graph tensor",
          "Captures both syntactic topology and variable semantics"],
         "#f0fdf4", "#86efac", title_color="#166534")

draw_box(ax, 0.665, 0.655, 0.310, 0.090,
         "Hybrid SAGEConv + GATConv GNN Core", "Deep Neural Optimization Predictor",
         ["Inductive neighbor aggregation via GraphSAGE layers",
          "Multi-Head Attention mechanism (GATConv) across CFG",
          "Learns complex inter-block deadness dependencies",
          "Outputs per-node elimination probability P(dead)"],
         "#f0fdf4", "#86efac", title_color="#166534")

# Connect Layer 1 to Layer 2
draw_arrow(ax, (0.860, 0.800), (0.860, 0.755), color=C_MUTED)
draw_arrow(ax, (0.860, 0.755), (0.485, 0.755), color=C_MUTED)
draw_arrow(ax, (0.485, 0.755), (0.485, 0.745), color=C_MUTED)
draw_arrow(ax, (0.620, 0.700), (0.665, 0.700), color=C_ACCENT_GREEN, lw=1.5)

# ------------------------------------------
# LAYER 3: Decision Arbitration & Safety Guarantees
# ------------------------------------------
# Box P6 [Mod 7]: Confidence Filter & HITL
draw_box(ax, 0.295, 0.490, 0.320, 0.115,
         "ML Confidence Filter & Active Learning", "Uncertainty Quantification & Retraining Loop",
         ["Confidence Gate: P(dead) > 0.85 (High), P < 0.15 (Live)",
          "Ambiguity Zone (0.45 <= P <= 0.65): Triggers HITL Queue",
          "Human-in-the-Loop review for anomalous edge cases",
          "Retraining Pipeline: logs corrections to active dataset",
          "Iterative model fine-tuning prevents systematic drift"],
         "#eff6ff", "#93c5fd", title_color="#1e40af",
         tag="Module 7", tag_bg="#dbeafe", tag_fg="#1e40af")

# Box P7 [Mod 3]: Safety Veto & Bug Triage
draw_box(ax, 0.655, 0.490, 0.320, 0.115,
         "Safety Veto & Bug Triage Engine", "Asymmetric Safety Verification Layer",
         ["Strict Side-Effect Auditor: volatile memory, I/O, syscalls",
          "Recursion Trap Resolver & infinite loop culling fix",
          "Def-Use invariant checking & memory safety guardian",
          "Rule of Safety: Heuristic veto unconditionally overrides",
          "Semantic equivalence preservation guarantee"],
         "#fef3c7", "#fcd34d", title_color="#b45309",
         tag="Module 3", tag_bg="#fef3c7", tag_fg="#b45309")

# Connect Layer 2 to Layer 3
draw_arrow(ax, (0.820, 0.655), (0.820, 0.605), color=C_ACCENT_GREEN, lw=1.5, label="P(dead)", label_pos=(0.840, 0.630))
draw_arrow(ax, (0.700, 0.655), (0.455, 0.605), color=C_ACCENT_BLUE, lw=1.3, rad=-0.1)

# Connect Module 7 to Module 3 (Arbiter)
draw_arrow(ax, (0.615, 0.540), (0.655, 0.540), color=C_ACCENT_BLUE, lw=1.5, label="Approved Candidates", label_pos=(0.635, 0.555))

# Active Learning Feedback Loop
draw_arrow(ax, (0.330, 0.605), (0.330, 0.700), color=C_ACCENT_BLUE, ls="--", rad=0.25, label="Feedback Retrain Loop", label_pos=(0.315, 0.650))
draw_arrow(ax, (0.330, 0.700), (0.665, 0.700), color=C_ACCENT_BLUE, ls="--")

# ------------------------------------------
# LAYER 4: Sandboxed Execution & Agentic Healing Loop
# ------------------------------------------
# Box P8 [Mod 5]: Sandbox
draw_box(ax, 0.295, 0.300, 0.320, 0.135,
         "Sandboxed Execution Engine", "Isolated Micro-Container & Verification Jail",
         ["Isolated Docker / Seccomp Linux namespace container",
          "Safe isolated compilation of user C/C++ code",
          "Executes test suite with strict CPU/memory timeouts",
          "Captures runtime exit codes, stdout, stderr, memory traps",
          "Prevents untrusted payloads from compromising host system"],
         "#fdf4ff", "#f0abfc", title_color="#86198f",
         tag="Module 5", tag_bg="#fae8ff", tag_fg="#86198f")

# Box P9 [Mod 6]: Autonomous Debugger Agent
draw_box(ax, 0.655, 0.300, 0.320, 0.135,
         "Autonomous Agentic Debugger", "Closed-Loop Observe-Diagnose-Suggest-Verify Cycle",
         ["OBSERVE: Captures test harness failures & regression errors",
          "DIAGNOSE: Correlates failing test back to eliminated CFG nodes",
          "SUGGEST: Generates AST/SSA patch & restores required nodes",
          "VERIFY: Automatically dispatches re-test inside Sandbox",
          "Self-healing regression loop ensures zero semantic deviation"],
         "#eff6ff", "#60a5fa", title_color="#1d4ed8",
         tag="Module 6", tag_bg="#dbeafe", tag_fg="#1d4ed8")

# Connect Layer 3 to Layer 4
draw_arrow(ax, (0.815, 0.490), (0.815, 0.435), color=C_ACCENT_AMBER, lw=1.5, label="Optimized IR", label_pos=(0.855, 0.460))
draw_arrow(ax, (0.815, 0.435), (0.455, 0.435), color=C_ACCENT_AMBER)

# Bidirectional Agentic Self-Healing Loop
draw_arrow(ax, (0.615, 0.380), (0.655, 0.380), color=C_ACCENT_PURPLE, lw=1.6, label="Execution Telemetry", label_pos=(0.635, 0.395))
draw_arrow(ax, (0.655, 0.335), (0.615, 0.335), color=C_ACCENT_BLUE, lw=1.6, ls="-", label="Auto-Fix Re-test", label_pos=(0.635, 0.320))

# ------------------------------------------
# LAYER 5: Developer Intelligence & UI Scorecard
# ------------------------------------------
# Box P10 [Mod 1]: Code Health Scorecard
draw_box(ax, 0.295, 0.040, 0.320, 0.205,
         "Program Vitality & Health Scorecard", "Comprehensive Quality & Security Analytics Dashboard",
         ["Formula-Driven Vitality Index (0–100 Rating)",
          "CFG Tangle Factor (Branch-to-Block Cyclomatic Ratio)",
          "Dead Code Elimination Density (Bytes & Statements)",
          "Quality Badges: EXCELLENT / GOOD / ATTENTION / CRITICAL",
          "Security Badges: SECURE / AT RISK / VULNERABLE",
          "Correlates static CWE triage flags with runtime vitality",
          "Gives developers instantaneous diagnostic confidence"],
         "#ecfdf5", "#6ee7b7", title_color="#065f46",
         tag="Module 1", tag_bg="#d1fae5", tag_fg="#065f46")

# Box P11 [Mod 4]: Agentic AI Explainer
draw_box(ax, 0.655, 0.040, 0.320, 0.205,
         "Agentic AI DCE Explainer & Dialogue", "Multi-Turn Interactive Compiler Assistant",
         ["Context-Aware Natural Language Explanations",
          "Root-Cause Semantics: explains WHY code became dead",
          "Actionable Upstream C++ Refactoring Fix Recommendations",
          "Interactive Multi-Turn Dialogue for developer queries",
          "Mode-Aware UX: toggles Classical vs Neural vs Agentic",
          "Human-in-the-Loop approval console for Module 7 edge cases",
          "Eliminates compiler opacity through grounded reasoning"],
         "#faf5ff", "#d8b4fe", title_color="#6b21a8",
         tag="Module 4", tag_bg="#f3e8ff", tag_fg="#6b21a8")

# Connect Layer 4 to Layer 5
draw_arrow(ax, (0.455, 0.300), (0.455, 0.245), color=C_ACCENT_TEAL, lw=1.5, label="Verified Metrics", label_pos=(0.455, 0.270))
draw_arrow(ax, (0.815, 0.300), (0.815, 0.245), color=C_ACCENT_PURPLE, lw=1.5, label="Verified Code & Diffs", label_pos=(0.815, 0.270))

# Interactive Dialogue between UI and Agentic Loop
draw_arrow(ax, (0.615, 0.140), (0.655, 0.140), color=C_MUTED, ls=":", lw=1.2)

# Global Footer
plt.text(0.5, 0.012, "Project: Intelligent Dead Code Elimination Tool (IntelliDCE) | Full Scope: Modules 1–7 System Architecture", 
         ha='center', va='center', fontsize=8.5, color=C_MUTED)

plt.tight_layout()

# Save both PDF and PNG to workspace and brain artifacts
out_pdf_ws = "IntelliDCE_Architecture_Specification.pdf"
out_png_ws = "IntelliDCE_Architecture_Specification.png"
out_pdf_brain = "/Users/rahulkumarchaurasiya/.gemini/antigravity-ide/brain/0f6ebf39-3753-4d02-b085-149e4785c289/IntelliDCE_Architecture_Specification.pdf"
out_png_brain = "/Users/rahulkumarchaurasiya/.gemini/antigravity-ide/brain/0f6ebf39-3753-4d02-b085-149e4785c289/IntelliDCE_Architecture_Specification.png"

plt.savefig(out_pdf_ws, format="pdf", bbox_inches='tight')
plt.savefig(out_png_ws, format="png", bbox_inches='tight', dpi=150)

import shutil
shutil.copy(out_pdf_ws, out_pdf_brain)
shutil.copy(out_png_ws, out_png_brain)

print("Architecture Diagram Generated Successfully!")
print(f"PDF Size: {os.path.getsize(out_pdf_ws) / 1024:.2f} KB")
print(f"PNG Size: {os.path.getsize(out_png_ws) / 1024:.2f} KB")
