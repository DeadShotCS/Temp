import re

# Expanded OS Map for diverse testing
OS_DATA = {
    "All Operating Systems": {},
    "Windows 10 22H2": {
        "ntoskrnl.exe": ["10.0.19041.1", "10.0.19041.500"],
        "hal.dll": ["10.0.19041.1", "10.0.19041.600"],
        "fltmgr.sys": ["10.0.19041.1"],
        "ci.dll": ["10.0.19041.1"]
    },
    "Windows 11 23H2": {
        "ntoskrnl.exe": ["10.0.22621.1"],
        "hal.dll": ["10.0.22621.1"],
        "win32k.sys": ["10.0.22621.1"]
    }
}

SYMBOL_DATA = {
    # --- NTOSKRNL 19041.1 ---
    "ntoskrnl.exe (10.0.19041.1)": {
        "functions": {
            "PsGetCurrentProcess": {
                "type": "export",
                "code": "struct _EPROCESS* PsGetCurrentProcess(void) {\n    return (struct _EPROCESS*)KeGetCurrentThread()->ApcState.Process;\n}"
            },
            "KeQueryPerformanceCounter": {
                "type": "import",
                "source_binary": "hal.dll",
                "code": "// Redirected to hal.dll"
            },
            "FltGetRoutineAddress": {
                "type": "import",
                "source_binary": "fltmgr.sys",
                "code": "// Redirected to fltmgr.sys"
            }
        },
        "structs": {
            "_EPROCESS": "struct _EPROCESS {\n    struct _KPROCESS Pcb;\n    uint32_t UniqueProcessId;\n};"
        }
    },
    # --- NTOSKRNL 19041.500 ---
    "ntoskrnl.exe (10.0.19041.500)": {
        "functions": {
            "PsGetCurrentProcess": {
                "type": "export",
                "code": "struct _EPROCESS* PsGetCurrentProcess(void) {\n    /* .500 Security Patch */\n    if (!PspIsContextValid()) return NULL;\n    return (struct _EPROCESS*)KeGetCurrentThread()->ApcState.Process;\n}"
            }
        },
        "structs": {}
    },
    # --- HAL.DLL Variations ---
    "hal.dll (10.0.19041.1)": {
        "functions": {
            "KeQueryPerformanceCounter": {
                "type": "export",
                "code": "LARGE_INTEGER KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency) {\n    return HalpGetPerformanceCounter();\n}"
            }
        },
        "structs": {}
    },
    "hal.dll (10.0.19041.600)": {
        "functions": {
            "KeQueryPerformanceCounter": {
                "type": "export",
                "code": "LARGE_INTEGER KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency) {\n    return HalpGetPerformanceCounterV2();\n}"
            }
        },
        "structs": {}
    },
    # --- FLTMGR ---
    "fltmgr.sys (10.0.19041.1)": {
        "functions": {
            "FltGetRoutineAddress": {
                "type": "export",
                "code": "PVOID FltGetRoutineAddress(PCSTR FltMgrRoutineName) {\n    return FltpGetRoutineAddress(FltMgrRoutineName);\n}"
            }
        },
        "structs": {}
    }
}


def get_all_filename_versions(os_filter="All Operating Systems"):
    results = {}
    if os_filter == "All Operating Systems":
        targets = [k for k in OS_DATA.keys() if k != "All Operating Systems"]
    else:
        targets = [os_filter]

    for os_name in targets:
        for fname, versions in OS_DATA.get(os_name, {}).items():
            if fname not in results:
                results[fname] = []
            results[fname] = list(set(results[fname] + versions))
            
    for fname in results:
        results[fname].sort(reverse=True)
    return results

def get_header(title, binary, symbol):
    return f"/*\n * {title}\n * Binary: {binary}\n * Search: {symbol}\n */\n"

def resolve_symbol_definition(target_bin_name, target_ver, symbol_name, original_full_string=None):
    current_full_string = f"{target_bin_name} ({target_ver})"
    if not original_full_string:
        original_full_string = current_full_string

    # 1. Check current binary
    if current_full_string in SYMBOL_DATA:
        bin_content = SYMBOL_DATA[current_full_string]
        if symbol_name in bin_content.get('functions', {}):
            f_data = bin_content['functions'][symbol_name]
            if f_data['type'] != 'import':
                is_redir = current_full_string != original_full_string
                return f_data['code'], current_full_string, None, is_redir
            else:
                return resolve_symbol_definition(f_data['source_binary'], target_ver, symbol_name, original_full_string)
        
        if symbol_name in bin_content.get('structs', {}):
            is_redir = current_full_string != original_full_string
            return bin_content['structs'][symbol_name], current_full_string, None, is_redir

    # 2. Version Fallback Logic
    all_bins = [k for k in SYMBOL_DATA.keys() if k.startswith(target_bin_name)]
    if all_bins:
        fallback_full_string = all_bins[0]
        fallback_ver = fallback_full_string.split('(')[1].replace(')', '')
        bin_content = SYMBOL_DATA[fallback_full_string]
        
        if symbol_name in bin_content.get('functions', {}):
            f_data = bin_content['functions'][symbol_name]
            if f_data['type'] != 'import':
                err = f"!!RED!! Version match failed for {target_ver}. Resolved via: {fallback_ver}"
                return f_data['code'], fallback_full_string, err, True
            else:
                return resolve_symbol_definition(f_data['source_binary'], fallback_ver, symbol_name, original_full_string)

    return None, None, f"Symbol '{symbol_name}' not found.", False

# THIS IS THE FUNCTION YOUR APP.PY IS CALLING
def perform_search(category, criteria):
    ver_src = criteria.get('full_version_string', '')
    ver_dst = criteria.get('destination_version_string', '')
    symbol_name = criteria.get('name', '').strip()

    # --- DIFF MODE ---
    if category == "diff":
        src_data = SYMBOL_DATA.get(ver_src)
        dst_data = SYMBOL_DATA.get(ver_dst)
        if not src_data or not dst_data:
            raise Exception("Binary selection incomplete for diff")
        
        def find_local(b_dict, name):
            if name in b_dict.get('functions', {}):
                item = b_dict['functions'][name]
                return ("import", None) if item['type'] == 'import' else ("function", item['code'])
            if name in b_dict.get('structs', {}):
                return ("struct", b_dict['structs'][name])
            return (None, None)

        s_type, s_code = find_local(src_data, symbol_name)
        d_type, d_code = find_local(dst_data, symbol_name)

        if s_type == "import" or d_type == "import":
           raise Exception("Cannot diff imports. Search in 'Symbol Search' to resolve source")

        return {
            "panes": [
                get_header("DIFF SOURCE", ver_src, symbol_name) + (s_code or "// Not found"),
                get_header("DIFF DESTINATION", ver_dst, symbol_name) + (d_code or "// Not found")
            ],
            "swaps": {}
        }

    # --- RESOLVER (SYMBOL / LIST) ---
    try:
        bin_name = ver_src.split(' (')[0]
        ver_num = ver_src.split('(')[1].replace(')', '')
    except:
        raise Exception("Select a valid binary")

    if category == "list" and (not symbol_name or symbol_name == "*"):
        data = SYMBOL_DATA.get(ver_src)
        if not data: return {"panes": ["// ERROR: Binary data missing."], "swaps": {}}
        header = get_header("SYMBOL LIST", ver_src, "*")
        out = [header, "/* --- FUNCTIONS --- */"] + sorted(data['functions'].keys())
        out += ["\n/* --- STRUCTURES --- */"] + sorted(data['structs'].keys())
        return {"panes": ["\n".join(out)], "swaps": {}}

    code, found_in_bin, error, is_redirect = resolve_symbol_definition(bin_name, ver_num, symbol_name)
    
    if code:
        title = "REDIRECTED DEFINITION" if is_redirect else "DEFINITION"
        header = get_header(title, found_in_bin, symbol_name)
        if error: header = f"// {error}\n" + header
        return {
            "panes": [header + code],
            "swaps": {"file_search": found_in_bin} if is_redirect else {}
        }
    
    raise Exception(f"{error}")