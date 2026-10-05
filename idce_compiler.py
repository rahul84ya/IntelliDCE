#!/usr/bin/env python3
import sys
import os
import subprocess
import re
import uuid

def main():
    if len(sys.argv) < 2:
        print("Usage: ./idce_compiler.py <input.cpp>")
        sys.exit(1)

    input_cpp = sys.argv[1]
    basename = os.path.basename(input_cpp).rsplit('.', 1)[0]
    out_dir = f"/tmp/idce_run_{uuid.uuid4().hex[:8]}"
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Starting IDCE Executing Compiler on {input_cpp}...")

    # 1. Compile with Line Numbers
    ssa_dump = os.path.join(out_dir, f"{basename}.021t.ssa")
    print("[*] Generating GIMPLE SSA with line numbers...")
    try:
        subprocess.run(
            ["g++", "-g", "-O0", "-fdump-tree-ssa-lineno", os.path.abspath(input_cpp)],
            cwd=out_dir, check=True, capture_output=True
        )
    except subprocess.CalledProcessError as e:
        print("[!] GCC Compilation failed:", e.stderr.decode('utf-8'))
        sys.exit(1)

    # Find the generated SSA relative to the out_dir
    possible_ssas = [f for f in os.listdir(out_dir) if f.endswith(".ssa")]
    if not possible_ssas:
        print("[!] Could not generate SSA dump.")
        sys.exit(1)
    
    raw_ssa_file = os.path.join(out_dir, possible_ssas[0])

    # 2. Extract Line Numbers & Strip them for IDCE Parity
    print("[*] Parsing SSA Line-Number Bindings...")
    stripped_ssa_file = os.path.join(out_dir, "stripped.ssa")
    
    lineno_map = {} # Maps stripped_text_fingerprint -> set of {line}
    
    with open(raw_ssa_file, 'r') as f_in, open(stripped_ssa_file, 'w') as f_out:
        for full_line in f_in:
            tags = re.findall(r'\[([^\]]+):(\d+):[^\]]+\]', full_line)
            stripped_line = re.sub(r'\[([^\]]+):(\d+):[^\]]+\]\s*', '', full_line)
            
            if tags:
                for file_path, line_idx_str in tags:
                    line_idx = int(line_idx_str)
                    if basename in file_path or os.path.basename(input_cpp) in file_path:
                        fingerprint = stripped_line.strip()
                        if fingerprint not in lineno_map:
                            lineno_map[fingerprint] = set()
                        lineno_map[fingerprint].add(line_idx)
            
            f_out.write(stripped_line)
    
    # 3. Process stripped SSA with IDCE
    print("[*] Dispatching to IDCE Machine Learning Node Predictor...")
    idce_out_dir = os.path.join(out_dir, "idce_out")
    os.makedirs(idce_out_dir, exist_ok=True)
    
    # WORKAROUND: Linux ntfs3 drivers segfault when executing binaries directly on Windows partitions.
    # We must copy `idce` to the /tmpfs partition and execute it there.
    import shutil
    tmp_idce_bin = os.path.join(out_dir, "idce_bin")
    try:
        shutil.copy2("./idce", tmp_idce_bin)
    except FileNotFoundError:
        print("[!] ./idce binary not found. Run `make` first.")
        sys.exit(1)

    try:
        idce_res = subprocess.run(
            [tmp_idce_bin, "--ml-dce", idce_out_dir],
            input=open(stripped_ssa_file, 'r').read(),
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        print("[!] IDCE Parser Error!")
        print(e.stderr)
        sys.exit(1)

    # 4. Map dead statements back to original C++ line numbers
    print("[*] Mapping ML Dead Code Extirpations back to Source...")
    
    dead_lines_target = set()
    for line in idce_res.stdout.split('\n'):
        if "Safely Removing" in line or "Removing dead entry" in line or "Removing unreachable Block" in line:
            parts = line.split("entry: ")
            if len(parts) > 1:
                stmt_text = parts[1].strip()
                if stmt_text.endswith(';'): stmt_text = stmt_text[:-1]
                
                for finger, ln_set in lineno_map.items():
                    if stmt_text in finger or finger in stmt_text:
                        for l in ln_set: dead_lines_target.add(l)

    # 5. Generate Optimized C++ Source
    optimized_cpp = "optimized_" + os.path.basename(input_cpp)
    tmp_optimized_cpp = os.path.join(out_dir, optimized_cpp)
    try:
        with open(input_cpp, 'r') as src:
            source_lines = src.readlines()
            
        with open(tmp_optimized_cpp, 'w') as out_cpp:
            for i, val in enumerate(source_lines):
                real_line = i + 1
                if real_line in dead_lines_target:
                    out_cpp.write(f"// [IDCE ML PRUNED] {val.rstrip()}\n")
                else:
                    out_cpp.write(val)
        
        # Copy to local dir so user can read it
        shutil.copy2(tmp_optimized_cpp, optimized_cpp)
    except Exception as e:
        print("[!] Failed writing source map:", e)
        sys.exit(1)

    print(f"[*] Generated Source Code: {optimized_cpp}")

    # 6. Final Executable Compilation
    print("[*] Finalizing Executable Generation...")
    executable = os.path.join(out_dir, "optimized_" + basename + ".out")
    try:
        subprocess.run(["g++", "-O0", tmp_optimized_cpp, "-o", executable], check=True)
    except subprocess.CalledProcessError:
        print(f"[!] Warning: GCC could not compile the optimized C++ stub.")
        sys.exit(1)
        
    print(f"\n[✓] SUCCESS: Output Executable Generated -> {executable}")
    print(f"You can now run: {executable} for proper output verification.")

if __name__ == "__main__":
    main()
