#!/usr/bin/env python3
# Based on original script by Xerpi!

import sys
import os
import csv

from collections import namedtuple
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from construct import Struct, Int8ub, Int16ub, Int32ub, PaddedString, CString, Array


ModuleImports = namedtuple("ModuleImports", "name nids")
ModuleExports = namedtuple("ModuleExports", "name nids")
ModuleInfo = namedtuple("ModuleNids", "name imports exports")
NIDNames = dict()
UnnamedNIDS = []

#ELFOSABI_CELL_LV2 = 0x66
ELFOSABI_CELL_LV2 = "ELFOSABI_CELL_LV2"
ET_SCE_PPURELEXEC = 0xFFA4
PT_PRX_PARAM = 0x60000002

sys_prx_module_info_t = Struct(
    "attributes" / Int16ub,
    "version" / Int16ub,
    "name" / PaddedString(28, "ascii"),
    "toc" / Int32ub,
    "exports_start" / Int32ub,
    "exports_end" / Int32ub,
    "imports_start" / Int32ub,
    "imports_end" / Int32ub,
)

sys_prx_module_exports_t = Struct(
    "size" / Int8ub,
    "unk0" / Int8ub,
    "version" / Int16ub,
    "attributes" / Int16ub,
    "num_func" / Int16ub,
    "num_var" / Int16ub,
    "num_tlsvar" / Int16ub,
    "info_hash" / Int8ub,
    "info_tlshash" / Int8ub,
    "unk1" / Int16ub,
    "name_addr" / Int32ub,
    "fnid_addr" / Int32ub,
    "fstub_addr" / Int32ub
)

sys_prx_module_imports_t = Struct(
    "size" / Int8ub,
    "unk0" / Int8ub,
    "version" / Int16ub,
    "attributes" / Int16ub,
    "num_func" / Int16ub,
    "num_var" / Int16ub,
    "num_tlsvar" / Int16ub,
    "info_hash" / Int8ub,
    "info_tlshash" / Int8ub,
    "unk1" / Int16ub,
    "name_addr" / Int32ub,
    "fnid_addr" / Int32ub,
    "fstub_addr" / Int32ub,
    "var_nid_table" / Int32ub,
    "var_entry_table" / Int32ub,
    "tls_nid_table" / Int32ub,
    "tls_entry_table" / Int32ub
)

sys_process_prx_param_t = Struct(
    "size" / Int32ub,
    "magic" / Int32ub,
    "version" / Int32ub,
    "unk0" / Int32ub,
    "libent_start" / Int32ub,
    "libent_end" / Int32ub,
    "libstub_start" / Int32ub,
    "libstub_end" / Int32ub,
    "ver" / Int16ub,
    "unk1" / Int16ub,
    "unk2" / Int32ub,
)

def usage():
    print("ps3nidreader by xerpi")
    print("Usage:\n\t" + sys.argv[0] + " file.elf")

def read_nids_ps3_prx(f, elffile):
    module_info_found = False

    # First LOAD-type segment p_paddr points to the module info
    for segment in elffile.iter_segments():
        if segment.header.p_type == 'PT_LOAD':
            p_offset = segment["p_offset"]
            f.seek(segment["p_paddr"])
            module_info = sys_prx_module_info_t.parse_stream(f)
            module_info_found = True
            break

    if not module_info_found:
        print("Error: can't find the module info", file=sys.stderr)
        exit(1)

    #modinfo = ModuleInfo(module_info["name"].decode('ascii'), [], [])
    modinfo = ModuleInfo(module_info["name"], [], [])

    exp_addr = p_offset + module_info["exports_start"]
    while exp_addr < p_offset + module_info["exports_end"]:
        f.seek(exp_addr)
        exports = sys_prx_module_exports_t.parse_stream(f)

        name = ""
        if exports["name_addr"]:
            f.seek(p_offset + exports["name_addr"])
            name = CString('ascii').parse_stream(f)

        f.seek(p_offset + exports["fnid_addr"])
        nids = Array(exports["num_func"], Int32ub).parse_stream(f)

        modimp = ModuleExports(name, nids)
        modinfo.exports.append(modimp)

        exp_addr += exports["size"]

    imp_addr = p_offset + module_info["imports_start"]
    while imp_addr < p_offset + module_info["imports_end"]:
        f.seek(imp_addr)
        imports = sys_prx_module_imports_t.parse_stream(f)

        f.seek(p_offset + imports["name_addr"])
        name = CString('ascii').parse_stream(f)

        f.seek(p_offset + imports["fnid_addr"])
        nids = Array(imports["num_func"], Int32ub).parse_stream(f)

        modimp = ModuleImports(name, nids)
        modinfo.imports.append(modimp)

        imp_addr += imports["size"]

    return modinfo

def read_nids_ps3_elf_bruteforce(f, elffile):
    modinfo = ModuleInfo("", [], [])

    # Find the exports section
    exports_idx = -1
    for idx, section in enumerate(elffile.iter_sections()):
        if section["sh_size"] > 0 and section["sh_size"] % 0x1C == 0:
            is_exports = True
            offset = 0
            while offset < section["sh_size"]:
                f.seek(section["sh_offset"] + offset)
                if Int8ub.parse_stream(f) != 0x1C:
                    is_exports = False
                    break
                offset += 0x1C

            if is_exports:
                exports_idx = idx
                break;

    if exports_idx == -1:
        print("Error: can't find the imports", file=sys.stderr)
        exit(1)

    # Find the imports section
    imports_idx = -1
    for idx, section in enumerate(elffile.iter_sections()):
        if section["sh_size"] > 0 and section["sh_size"] % 0x2C == 0:
            is_imports = True
            offset = 0
            while offset < section["sh_size"]:
                f.seek(section["sh_offset"] + offset)
                if Int8ub.parse_stream(f) != 0x2C:
                    is_imports = False
                    break
                offset += 0x2C

            if is_imports:
                imports_idx = idx
                break;

    if imports_idx == -1:
        print("Error: can't find the imports", file=sys.stderr)
        exit(1)

    exp_section = elffile.get_section(exports_idx)
    exp_sh_offset = exp_section["sh_offset"]
    exp_sh_addr = exp_section["sh_addr"]
    exp_offset = 0
    while exp_offset < exp_section["sh_size"]:
        f.seek(exp_sh_offset + exp_offset)
        exports = sys_prx_module_exports_t.parse_stream(f)
        name = ""
        if exports["name_addr"]:
            f.seek(exports["name_addr"] + (exp_sh_offset - exp_sh_addr))
            name = CString("ascii").parse_stream(f)

        f.seek(exports["fnid_addr"] + (exp_sh_offset - exp_sh_addr))
        nids = Array(exports["num_func"], Int32ub).parse_stream(f)

        modexp = ModuleExports(name, nids)
        modinfo.exports.append(modexp)

        exp_offset += exports["size"]

    imp_section = elffile.get_section(imports_idx)
    imp_sh_offset = imp_section["sh_offset"]
    imp_sh_addr = imp_section["sh_addr"]
    imp_offset = 0
    while imp_offset < imp_section["sh_size"]:
        f.seek(imp_sh_offset + imp_offset)
        imports = sys_prx_module_imports_t.parse_stream(f)
        name = ""
        if imports["name_addr"]:
            f.seek(imports["name_addr"] + (imp_sh_offset - imp_sh_addr))
            name = CString("ascii").parse_stream(f)

        f.seek(imports["fnid_addr"] + (imp_sh_offset - imp_sh_addr))
        nids = Array(imports["num_func"], Int32ub).parse_stream(f)

        modimp = ModuleImports(name, nids)
        modinfo.imports.append(modimp)

        imp_offset += imports["size"]

    return modinfo

def read_nids_ps3_elf(f, elffile):
    prx_param_found = False

    # PT_PRX_PARAM segment has the process PRX param
    for segment in elffile.iter_segments():
        if segment.header.p_type == PT_PRX_PARAM:
            p_offset = segment["p_offset"]
            p_paddr = segment["p_paddr"]
            if segment["p_offset"] == 0:
                return read_nids_ps3_elf_bruteforce(f, elffile)
            f.seek(segment["p_offset"])
            prx_param = sys_process_prx_param_t.parse_stream(f)
            prx_param_found = True
            break

    if not prx_param_found:
        print("Error: can't find the PRX param segment", file=sys.stderr)
        exit(1)

    modinfo = ModuleInfo("", [], [])

    exp_addr = p_offset + (prx_param["libent_start"] - p_paddr)
    while exp_addr < p_offset + (prx_param["libent_end"] - p_paddr):
        f.seek(exp_addr)
        exports = sys_prx_module_exports_t.parse_stream(f)

        name = ""
        if exports["name_addr"]:
            f.seek(p_offset + (exports["name_addr"] - p_paddr))
            name = CString("ascii").parse_stream(f)

        f.seek(p_offset + (exports["fnid_addr"] - p_paddr))
        nids = Array(exports["num_func"], Int32ub).parse_stream(f)

        modexp = ModuleExports(name, nids)
        modinfo.exports.append(modexp)

        exp_addr += exports["size"]

    imp_addr = p_offset + (prx_param["libstub_start"] - p_paddr)
    while imp_addr < p_offset + (prx_param["libstub_end"] - p_paddr):
        f.seek(imp_addr)
        imports = sys_prx_module_imports_t.parse_stream(f)

        f.seek(p_offset + (imports["name_addr"] - p_paddr))
        name = CString("ascii").parse_stream(f)

        f.seek(p_offset + (imports["fnid_addr"] - p_paddr))
        nids = Array(imports["num_func"], Int32ub).parse_stream(f)

        modimp = ModuleImports(name, nids)
        modinfo.imports.append(modimp)

        imp_addr += imports["size"]

    return modinfo

def print_nids(modinfo):
    print("Module name: " + modinfo.name)

    print("  Exports:")

    for exp in modinfo.exports:
        if exp.name:
            print("    " + exp.name)
        else:
            print("    <no name>")
        for nid in exp.nids:
            nid_formatted = "0x{:08X}".format(nid)
            if(nid_formatted in NIDNames):
                print("      " + nid_formatted + " " + NIDNames[nid_formatted])
            else:
                print("      " + nid_formatted + " ")


    #print("  Imports:")

    #for imp in modinfo.imports:
    #    print("    " + imp.name)
    #    for nid in imp.nids:
    #        print("      " + "0x{:08X}".format(nid))

def print_nids_yaml(modinfo):
    # We only care about exports
    if len(modinfo.exports) == 0:
        return
    print("modules:")
    print("  " + modinfo.name + ":")
    print("    libraries:")

    for exp in modinfo.exports:
        if not exp.name:
            continue

        print("      " + exp.name + ":")
        print("        functions:")

        # ----- collect functions -----
        functions = []
        for nid in exp.nids:
            nid_formatted = f"0x{nid:08X}"
            if nid_formatted in NIDNames:
                funcname = NIDNames[nid_formatted]
            else:
                funcname = f"{exp.name}_{nid_formatted}"
                UnnamedNIDS.append(modinfo.name + " : " + nid_formatted + "\n")
            functions.append((funcname, nid_formatted))

        # ----- sort alphabetically by function name -----
        functions.sort(key=lambda x: x[0])

        # ----- print sorted -----
        for funcname, nid_formatted in functions:
            print(f"          {funcname}: {nid_formatted}")


def process_file(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if elffile.header.e_ident["EI_OSABI"] == ELFOSABI_CELL_LV2:
            if elffile.header.e_type == ET_SCE_PPURELEXEC:
                modinfo = read_nids_ps3_prx(f, elffile)
            elif elffile.header.e_type == "ET_EXEC":
                modinfo = read_nids_ps3_elf(f, elffile)

            #print_nids(modinfo)
            print_nids_yaml(modinfo)
        else:
            print("Error: not a PS3 PPU ELF", file=sys.stderr)
            exit(1)

def parse_nid_names(filename):
    with open(filename, 'rt') as f:
        nidnamereader = csv.reader(f, delimiter=" ")
        for row in nidnamereader:
            NIDNames[row[0]] = row[1]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        parse_nid_names("nids.txt")
        process_file(sys.argv[1])