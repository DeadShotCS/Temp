# A Ghidra Python script to dump all function decompilation
# to individual files, organized by namespace-like prefixes.
# @author The AI
# @category Export
# @keybinding Ctrl+Shift+D
# @menupath Tools.Script.Dump All Decompilations
# @toolbar

import os
import sys
import shutil
import time
import re

# Check if we have a program loaded
if currentProgram is None:
    print("No program is currently open. Please open a program and run the script again.")
    exit()

def get_script_dir():
    """
    Find the directory where the current script is located.
    """
    try:
        script_file_path = __file__
        return os.path.dirname(os.path.abspath(script_file_path))
    except NameError:
        return os.path.dirname(os.path.realpath(sys.argv[0]))

def get_program_info():
    """
    Retrieves the program name and its SHA256 hash.
    """
    program_name = currentProgram.getName()
    program_hash = currentProgram.getExecutableSHA256()
    return program_name, program_hash

def get_decompiler_interface():
    """
    Initializes and returns a DecompInterface object.
    """
    from ghidra.app.decompiler import DecompInterface
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    return decompiler

def sanitize_filename(name):
    """
    Sanitizes a string to be a valid filename, replacing
    unsupported characters.
    """
    invalid_chars = '<>:"/\\|?* '
    for char in invalid_chars:
        name = name.replace(char, '_')
    return name

def get_namespace_path(function):
    """
    Builds a hierarchical directory path from a function's namespace.
    """
    namespace_path_list = []
    parent_namespace = function.getParentNamespace()

    while parent_namespace and not parent_namespace.isGlobal():
        namespace_path_list.insert(0, sanitize_filename(parent_namespace.getName()))
        parent_namespace = parent_namespace.getParentNamespace()
    
    if not namespace_path_list:
        return ""
        
    return os.path.join(*namespace_path_list)

def get_prefix_group(function_name):
    """
    Determines a prefix for grouping a function name.
    """
    if function_name.startswith("FUN_"):
        return "Ghidra_Generated_Functions"
    elif "_" in function_name:
        return sanitize_filename(function_name.split("_")[0])
    elif "::" in function_name:
        return sanitize_filename(function_name.split("::")[0])
    elif len(function_name) > 0:
        return sanitize_filename(function_name[0])
    return "Other"

def dump_functions_to_files():
    """
    The main function to orchestrate the decompilation and file writing.
    """
    program_name, program_hash = get_program_info()
    
    base_dir = get_script_dir()
    output_dir_name = "{}_{}".format(program_name, program_hash)
    output_dir = os.path.join(base_dir, output_dir_name)
    
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)
    
    print("Dumping decompilation to directory: {}".format(output_dir))
    
    decompiler = get_decompiler_interface()
    
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    total_functions = function_manager.getFunctionCount()
    
    monitor.setMessage("Dumping all functions...")
    
    for i, function in enumerate(functions):
        if monitor.isCancelled():
            break
            
        function_name = function.getName()
        monitor.setProgress(i)
        monitor.setMaximum(total_functions)
        monitor.setMessage("Decompiling {} ({}/{})...".format(function_name, i + 1, total_functions))
        
        decomp_results = decompiler.decompileFunction(function, 0, monitor)
        
        if decomp_results.decompileCompleted():
            decompiled_code = decomp_results.getDecompiledFunction().getC()
            
            # Split the code into lines
            lines = decompiled_code.split('\n')
            
            # Remove empty lines and strip whitespace from each line
            cleaned_lines = []
            for line in lines:
                stripped_line = line.rstrip()  # Remove trailing whitespace
                if stripped_line:
                    cleaned_lines.append(stripped_line)
            
            # Join the lines back into a single string
            cleaned_code = '\n'.join(cleaned_lines)
            
            namespace_path = get_namespace_path(function)
            
            if not namespace_path:
                namespace_path = get_prefix_group(function_name)
            
            target_dir = os.path.join(output_dir, namespace_path)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            safe_func_name = sanitize_filename(function_name)
            if not safe_func_name:
                safe_func_name = "Unnamed_Function_{}".format(function.getEntryPoint())
                
            file_path = os.path.join(target_dir, "{}.c".format(safe_func_name))
            
            try:
                with open(file_path, "w") as f:
                    f.write(cleaned_code)
            except Exception as e:
                print("Error writing to file for function {}: {}".format(function_name, e))
        else:
            print("Failed to decompile function: {} ({})".format(function_name, decomp_results.getErrorMessage()))
            time.sleep(1)

    print("Decompilation dump complete!")
    decompiler.dispose()
    
dump_functions_to_files()