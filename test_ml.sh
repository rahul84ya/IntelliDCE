#!/bin/bash

# Simple script to automate GIMPLE SSA generation and IDCE ML DCE testing

if [ "$#" -ne 1 ]; then
    echo "Usage: ./test_ml.sh <cpp_file>"
    exit 1
fi

CPP_FILE=$1
BASENAME=$(basename "$CPP_FILE" .cpp)

echo "[1/3] Compiling $CPP_FILE to generate GIMPLE SSA..."
g++ -O0 -fdump-tree-ssa "$CPP_FILE" -o /tmp/dummy_out

# Locate the generated SSA file. GCC generates something like a-<basename>.cpp.021t.ssa or <basename>.cpp.021t.ssa
SSA_FILE=$(find . -maxdepth 1 -name "*${BASENAME}*.ssa" | head -n 1)

if [ -z "$SSA_FILE" ]; then
    echo "[!] Error: Could not locate generated .ssa file."
    exit 1
fi

echo "[2/3] Found SSA target: $SSA_FILE"
echo ""

OUT_PREFIX="output_${BASENAME}_mldce"

echo "[3/3] Running IDCE in --ml-dce mode..."
# Pass the SSA file directly via stdin
./idce --ml-dce "$OUT_PREFIX" < "$SSA_FILE"

RET=$?

if [ $RET -ne 0 ]; then
    echo ""
    echo "[X] IDCE encountered an error (Code: $RET). Note that complex C++ constructs like vectors occasionally trigger the parser segfault issue."
    exit $RET
fi

echo ""
echo "[✓] IDCE Analysis Complete!"
echo "Check the detailed generated pipeline results in: ./${OUT_PREFIX}/"
echo ""

if [ -f "${OUT_PREFIX}/summary.txt" ]; then
    echo "=== Summary Output ==="
    cat "${OUT_PREFIX}/summary.txt"
fi

if [ -f "${OUT_PREFIX}/optimized.ssa" ]; then
    echo ""
    echo "The repaired and optimized SSA is located at: ${OUT_PREFIX}/optimized.ssa"
fi
