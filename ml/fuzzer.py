#!/usr/bin/env python3
import random
import string
import os

var_counter = 0

def get_new_var():
    global var_counter
    var_counter += 1
    return f"v_{var_counter}"

def rand_existing_var():
    if var_counter == 0:
        return get_new_var()
    return f"v_{random.randint(1, var_counter)}"

def rand_num():
    return str(random.randint(0, 100))

def rand_op():
    return random.choice(['+', '-', '*', '/'])

def gen_assignment():
    lhs = get_new_var()
    choice = random.random()
    if choice < 0.3:
        rhs = rand_num()
    elif choice < 0.6:
        rhs = rand_existing_var()
    else:
        rhs = f"{rand_existing_var()} {rand_op()} {rand_num() if random.random() < 0.5 else rand_existing_var()}"
    return f"    {lhs} = {rhs};\n"

def gen_dead_store():
    lhs = get_new_var()
    return f"    {lhs} = {rand_num()};\n"

def gen_if(max_blocks):
    cond = f"{rand_existing_var()} {random.choice(['==', '!=', '<', '>'])} {rand_num()}"
    return f"    if ({cond}) goto <bb {random.randint(1, max_blocks)}>;\n"

def gen_call():
    func = random.choice(["printf", "malloc", "compute", "helper"])
    return f"    {func}({rand_existing_var()});\n"

def generate_function(name):
    global var_counter
    var_counter = 0

    code = f";; Function {name} ({name})\n\n{name} () {{\n"
    for i in range(1, 6):
        get_new_var()
        code += f"    int v_{i};\n"

    blocks = random.randint(3, 7)
    for b in range(1, blocks + 1):
        code += f"  <bb {b}>:\n"
        stmts = random.randint(3, 12)
        for _ in range(stmts):
            c = random.random()
            if c < 0.1: code += gen_dead_store()
            elif c < 0.2: code += gen_call()
            else: code += gen_assignment()

        if b < blocks:
            code += gen_if(blocks)
            code += f"    goto <bb {b+1}>;\n"
        else:
            code += f"    return {rand_existing_var()};\n"

    code += "}\n\n"
    return code

def generate_program(filepath):
    code = generate_function("main")
    for i in range(random.randint(0, 2)):
        code += generate_function(f"func_{i}")

    with open(filepath, 'w') as f:
        f.write(code)

if __name__ == "__main__":
    os.makedirs("ml_data/raw", exist_ok=True)
    print("Generating 100 training programs...")
    for i in range(100):
        generate_program(f"ml_data/raw/fuzz_{i}.txt")
    print("Fuzzing complete. Files saved to ml_data/raw/")
