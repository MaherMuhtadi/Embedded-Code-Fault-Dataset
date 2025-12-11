import re
import os
from openpyxl import Workbook

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(SCRIPT_DIR, "itc-benchmarks")
SUBDIRS = ["01.w_Defects", "02.wo_Defects"]
ALL_ROWS = []
KEYWORDS = {
            "if","for","while","switch","return","sizeof","case","else","goto"
        }


# Remove comment-only lines

def strip_comment_only_lines(code):
    cleaned = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or (stripped.startswith("/*") and stripped.endswith("*/")):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


# Extract top-level global variable declarations

def extract_global_variables(code):
    globals_list = []
    brace_depth = 0

    for line in code.splitlines():
        stripped = line.strip()

        brace_depth += line.count("{") - line.count("}")

        if brace_depth == 0:
            # Crude but effective top-level variable detector
            if re.match(r'^[a-zA-Z_].*?;', stripped) and "(" not in stripped:
                globals_list.append(line)

    return globals_list


# Extract useful macro lines (only #define)

def extract_useful_macros(code):
    useful = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("#define"):
            parts = stripped.split()
            if len(parts) >= 3:
                useful.append(line)
    return useful


def filter_relevant_macros(macros, merged_code):
    relevant = []
    for m in macros:
        name = m.split()[1]   # macro name
        if name in merged_code:
            relevant.append(m)
    return relevant


# Extract typedef blocks for anonymous struct/union of the form:
# typedef struct { ... } Name;
# typedef union  { ... } Name;
# Returns a mapping { type_name : full_text_block }.

def extract_struct_typedefs(code):
    structs = {}

    pattern = re.compile(
        r'typedef\s+(struct|union)\s*\{([^}]*)\}\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*;',
        re.DOTALL
    )
    for match in pattern.finditer(code):
        kind, body, name = match.groups()
        full_block = f"typedef {kind} {{\n{body}}} {name};"
        structs[name] = full_block
    return structs


# Extract function blocks

def extract_function_blocks(code):
    functions = {}

    func_pattern = re.compile(
        r'([a-zA-Z_][a-zA-Z0-9_*\s]*?)\b'     # return type + pointers, up to last identifier boundary
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*'        # function name
        r'\(([^)]*)\)\s*\{',                  # arguments
        re.MULTILINE
    )

    for match in func_pattern.finditer(code):
        return_type, name, args = match.groups()

        if name in KEYWORDS:
            continue

        start = match.start()

        # Match braces for function body
        brace_count = 0
        i = match.end()

        while i < len(code):
            if code[i] == "{":
                brace_count += 1
            elif code[i] == "}":
                if brace_count == 0:
                    end = i + 1
                    break
                brace_count -= 1
            i += 1
        else:
            continue

        functions[name] = code[start:end]

    return functions


# Find referenced functions (ANY reference: comparison, assignment, call, pointer use)

def find_functions_referenced(func_code, func_blocks):
    referenced = set()
    for fname in func_blocks.keys():
        # match whole identifier (not substring)
        if re.search(r'\b' + re.escape(fname) + r'\b', func_code):
            referenced.add(fname)
    return referenced


# Recursively merge helper functions

def collect_recursive(func, func_blocks):
    collected = {}
    stack = [func]

    while stack:
        f = stack.pop()
        if f in collected:
            continue
        if f not in func_blocks:
            continue

        collected[f] = func_blocks[f]

        # detect all referenced functions
        referenced = find_functions_referenced(func_blocks[f], func_blocks)
        for r in referenced:
            if r in func_blocks and r not in collected and r != f:
                stack.append(r)

    return "\n".join(collected[f] for f in collected)


# Determine which struct typedefs are used by merged function block

def find_structs_used(merged_code, struct_typedefs):
    used = set()
    for name in struct_typedefs.keys():
        if re.search(r'\b' + re.escape(name) + r'\b', merged_code):
            used.add(name)
    return used


# Main Logic

def main(c_file, label):
    with open(c_file, "r") as f:
        c_code = f.read()

    # Clean code (remove comment-only lines, keep main functions)
    c_code = strip_comment_only_lines(c_code)

    # Extract components
    macros = extract_useful_macros(c_code)
    global_vars = extract_global_variables(c_code)
    struct_typedefs = extract_struct_typedefs(c_code)
    func_blocks = extract_function_blocks(c_code)

    if not func_blocks:
        print(f"No functions found in {c_file}")
        return

    # Find the driver function (*_main preferred, fallback to plain main)
    main_name = None
    main_candidates = [name for name in func_blocks.keys() if name.endswith("_main")]
    if main_candidates:
        main_name = main_candidates[0]
    elif "main" in func_blocks:
        main_name = "main"

    # Determine top-level functions
    if main_name is not None:
        # Top-level functions are those referenced (textually) from *_main/plain main
        direct_from_main = find_functions_referenced(func_blocks[main_name], func_blocks)
        top_level_funcs = sorted(
            f for f in direct_from_main
            if f in func_blocks and f != main_name
        )

        # Fallback: if we somehow found none, use all non-main functions
        if not top_level_funcs:
            top_level_funcs = sorted(
                f for f in func_blocks.keys() if f != main_name
            )
    else:
        # No obvious main: treat all functions as top-level
        top_level_funcs = sorted(func_blocks.keys())

    # Process each top-level function
    for func in top_level_funcs:
        # Merge this function with all helpers it references (recursively)
        merged_code = collect_recursive(func, func_blocks)

        # Only include struct/union typedefs referenced by this merged block
        structs_needed = find_structs_used(merged_code, struct_typedefs)
        struct_blocks = [struct_typedefs[s] for s in structs_needed]

        # Build a temporary header WITHOUT macros
        header_without_macros = ""
        if struct_blocks:
            header_without_macros += "\n".join(struct_blocks) + "\n"
        if global_vars:
            header_without_macros += "\n".join(global_vars) + "\n"

        # Now test macros against full context
        macro_blocks = filter_relevant_macros(macros, merged_code + header_without_macros)

        # Now assemble prepend_pieces in correct order
        prepend_pieces = []
        prepend_pieces.extend(macro_blocks)
        prepend_pieces.extend(struct_blocks)
        prepend_pieces.extend(global_vars)

        if prepend_pieces:
            prepend_block = "\n".join(prepend_pieces)
            merged_full = prepend_block + "\n" + merged_code
        else:
            merged_full = merged_code

        single_line = " ".join(merged_full.split())
        c_file_dirname = c_file.replace("\\", "/")
        c_file_dirname = "/".join(c_file_dirname.split("/")[-3:])

        ALL_ROWS.append([c_file_dirname, func, single_line, label])


# Entry point

if __name__ == "__main__":

    for sub in SUBDIRS:
        folder = os.path.join(ROOT, sub)

        if sub == "01.w_Defects":
            label = 1
        else:
            label = 0

        for fname in os.listdir(folder):

            # Skip files we do NOT want
            if fname in ("main.c", "Makefile.am", "stubs.c"):
                continue
            if not fname.endswith(".c"):
                continue

            full_path = os.path.join(folder, fname)
            print(f"Processing: {full_path}")
            main(full_path, label)
    
    # Write combined dataset
    combined_wb = Workbook()
    combined_ws = combined_wb.active
    combined_ws.title = "Combined"
    combined_ws.append(["Directory", "Function Name", "Code", "Label"])

    for row in ALL_ROWS:
        combined_ws.append(row)

    combined_output = os.path.join(SCRIPT_DIR, "dataset.xlsx")
    combined_wb.save(combined_output)
    print(f"\nCombined Excel file created: {combined_output}\n")
