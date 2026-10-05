# IDCE — ML-Assisted Dead Code Elimination

A research-level compiler backend prototype that eliminates dead code from **GIMPLE SSA IR** using both classical compiler analysis techniques and a **Graph Neural Network (GraphSAGE)** inference pipeline. Includes a web-based GUI for interactive visualization.

---

## Overview

IDCE takes a **Static Single Assignment (SSA)** intermediate representation file as input, builds a **Control Flow Graph (CFG)**, and eliminates dead instructions through one of two passes:

| Mode | Technique |
|------|-----------|
| **Classical DCE** | Constant folding (SCCP) → unreachable block pruning → liveness analysis (mark & sweep) → dead store elimination |
| **ML-Guided DCE** | GraphSAGE GNN predicts dead nodes on the CFG → safety veto via side-effect analysis → intelligent sweep |

---

## Project Structure

```
IDCE/
├── lexer.l                  # Flex lexer for GIMPLE SSA
├── parser.y                 # Bison parser → builds ProgramIR
├── ir.h                     # IR data structures (Statement, BasicBlock, FunctionIR)
├── analysis.cpp             # All DCE passes (SCCP, Liveness, DSE, ML-guided)
├── main.cpp                 # Entry point, DOT/report export
├── Makefile                 # Build system
│
├── ml/
│   ├── model.py             # DCENodeClassifier (GraphSAGE, 2-layer)
│   ├── train.py             # Training loop with precision/recall eval
│   ├── inference.py         # Runs inference on a CFG JSON, outputs dead_ids
│   ├── dataset_gen.py       # Processes raw CFG JSONs into PyG dataset
│   ├── fuzzer.py            # Generates synthetic SSA programs for training data
│   └── feature_extractor.cpp# Exports IR → JSON graph (nodes + edges + features)
│
├── ml_data/
│   ├── dce_model.pt         # Trained model weights
│   └── processed/           # PyTorch Geometric dataset (auto-generated)
│
├── inputs/                  # Sample SSA input files
│
├── gui/
│   ├── server.js            # Express + WebSocket backend
│   ├── public/index.html    # Frontend (CFG visualizer, log console, stats)
│   └── package.json
│
└── .gitignore
```

---

## Installation & Setup

Choose your operating system to install the required system dependencies (C++ compiler, Flex, Bison, and Graphviz).

### 1. System Dependencies

<details>
<summary><b>Linux (Ubuntu/Debian)</b></summary>

```bash
sudo apt update
sudo apt install -y g++ flex bison graphviz nodejs npm python3-pip python3-venv
```
</details>

<details>
<summary><b>Linux (Fedora)</b></summary>

```bash
sudo dnf install gcc-c++ flex bison graphviz nodejs python3-pip
```
</details>

<details>
<summary><b>Linux (Arch)</b></summary>

```bash
sudo pacman -S gcc flex bison graphviz nodejs npm python-pip
```
</details>

<details>
<summary><b>macOS (Homebrew)</b></summary>

```bash
brew install gcc flex bison graphviz nodejs
# Add Homebrew bison/flex to PATH (Apple's versions are too old)
export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
```
</details>

<details>
<summary><b>Windows</b></summary>

**Recommended: WSL2 (Windows Subsystem for Linux)**
1. Install [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install) with an Ubuntu distribution.
2. Follow the **Ubuntu/Debian** instructions above within your WSL terminal.

**Alternative: MSYS2 / MinGW**
1. Install [MSYS2](https://www.msys2.org/).
2. Run the MSYS2 UCRT64 terminal and install:
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-flex mingw-w64-x86_64-bison mingw-w64-x86_64-graphviz
   ```
</details>

---

### 2. ML Pipeline Setup (Python)

Requires **Python 3.12+**.

```bash
cd ml
python3 -m venv .venv

# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
# .\.venv\Scripts\Activate.ps1

pip install torch torch_geometric --index-url https://download.pytorch.org/whl/cpu
```

---

### 3. GUI Setup (Node.js)

Requires **Node.js 18+**.

```bash
cd gui
npm install
```

---

## Building

```bash
make
```

This compiles `lex.yy.c`, `parser.tab.c`, `main.cpp`, `analysis.cpp`, and `ml/feature_extractor.cpp` into the `idce` binary.

To clean:
```bash
make clean
```

---

## Usage

### Classical DCE

```bash
./idce <output_folder> < input.ssa
```

Example:
```bash
./idce analysis_report < inputs/input.ssa
```

Outputs:
- `analysis_report/summary.txt` — function/block/statement counts after optimization
- `analysis_report/graph.dot` — CFG in DOT format

Render the CFG image:
```bash
dot -Tpng analysis_report/graph.dot -o analysis_report/graph.png
```

---

### ML-Guided DCE

Requires a trained model at `ml_data/dce_model.pt`.

```bash
./idce <output_folder> --ml-dce < input.ssa
```

The pipeline:
1. Extracts IR features → `tmp_ir_graph.json`
2. Runs `ml/inference.py` → predicts dead instruction IDs
3. `applyIntelligentDCE()` removes predicted dead statements guarded by `hasSideEffect()` veto

---

## ML Pipeline

### 1. Generate Training Data

The fuzzer generates random SSA programs, compiles them through the parser, exports before/after CFG JSONs, and pairs them as labeled training samples.

```bash
cd ml
source .venv/bin/activate
python3 fuzzer.py          # generates synthetic .ssa files
python3 dataset_gen.py     # builds ml_data/processed/dataset.pt
```

### 2. Train the Model

```bash
python3 train.py
```

Training config:
- **Architecture:** 2-layer GraphSAGE → Linear classifier
- **Input features:** `[opcode_embedding, has_side_effect]` (dim = 2)
- **Loss:** `BCEWithLogitsLoss` with `pos_weight=0.2` (penalizes false positives — deleting live code is fatal)
- **Epochs:** 40, **Optimizer:** Adam (lr=0.01), **Split:** 80/20

Trained weights saved to `ml_data/dce_model.pt`.

### 3. Run Inference

```bash
python3 inference.py <ir_graph.json> ml_data/dce_model.pt
```

Outputs a JSON array of predicted dead instruction IDs to stdout.

---

## IR Extraction Flag

To export the raw CFG as JSON (without running DCE) — useful for dataset generation:

```bash
./idce <output_folder> --ml-extract < input.ssa
```

Outputs:
- `ir_graph_features.json` — pre-DCE graph
- `ir_graph_optimized.json` — post-DCE graph (ground truth labels)

---

## GUI

An interactive web frontend that runs the full pipeline through a browser.

```bash
cd gui
npm start
```

Open **http://localhost:3000**

### Features
| Panel | Description |
|-------|-------------|
| **Dashboard** | Stats after analysis — functions, blocks, live statements, removed instructions |
| **CFG View** | Interactive CFG rendered from `.dot` output using Viz.js; zoom + download |
| **Analysis Logs** | Color-coded real-time log stream via WebSocket |
| **Model Info** | GNN architecture, training config, and safety override explanation |

Supports uploading custom `.ssa` files or running the built-in sample inputs directly.

---

## DCE Passes (Classical)

| Phase | Implementation | Effect |
|-------|---------------|--------|
| **A — SCCP** | `applyConstantFolding()` | Evaluates constant expressions, prunes unreachable branches |
| **B — Reachability** | `removeUnreachableBlocks()` | BFS from entry block, removes dead basic blocks |
| **C — Inter-procedural** | `removeUnusedFunctions()` | Removes functions never called from `main` |
| **D — Liveness + DSE** | `applyDCE()` | Mark-and-sweep on variables; removes dead stores |

---

## Safety in ML Mode

Even when the GNN flags an instruction as dead, `hasSideEffect()` in `analysis.cpp` acts as a hard veto:

- Calls to `printf`, `scanf`, `malloc`, `free`, `fopen`, etc. → **never removed**
- Pointer-dereference assignments (`*ptr = ...`) → **never removed**
- All vetoed predictions are logged as `[ML DCE Warning]`

---

## Example Output

```
[DCE Log] Removing unreachable Block 3
[DCE Log] SCCP Evaluated Math: x_2 = 10
[DCE Log] Removing dead entry (DSE/Liveness): temp_1 = x_2 + 4
[ML DCE Log] Safely Removing predicted dead entry: _2 = _1 + 5
[ML DCE Warning] Vetoed ML prediction due to side effect: printf(...)
Analysis complete. Intermediate logs generated.
Files generated in folder: ./analysis_report
```

---

## License

MIT
