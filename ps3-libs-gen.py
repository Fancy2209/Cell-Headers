#!/usr/bin/env python3

import sys
import yaml

def usage():
	print("ps3-libs-gen by xerpi")
	print("Usage:\n\t" + sys.argv[0] + " file.yaml")

def generate_lib_resident(name):
	print("\t.section \".rodata.sceResident\", \"a\"")
	print("version:")
	print("\t.long " + hex(0))
	print("name:")
	print("\t.asciz \"" + name + "\"")

def generate_lib_stub(name):
	print("\t.section \".lib.stub\", \"a\"")
	print("\t.long " + hex(0x2c000001))
	print("\t.short " + hex(0x009))
	print("\t.short 0")
	print("\t.long 0")
	print("\t.long 0")
	print("\t.long name")
	print("\t.long " + name)
	print("\t.long sceFStub")
	print("\t.long 0")
	print("\t.long 0")
	print("\t.long 0")
	print("\t.long 0")

def generate_fstub(name):
	print("\t.align 2")
	print("\t.section \".sceStub.text\", \"ax\"")
	print("\t.globl __" + name)
	print("__" + name + ":")
	print("\tmflr	r0")
	print("\tstd	r0, 16(r1)")
	print("\tstdu	r1, -128(r1)")
	print("\tstd	r2, 112(r1)")
	print("\tlis	r12, " + name + "_stub@ha")
	print("\tlwz	r12, " + name + "_stub@l(r12)")
	print("\tlwz	r0, 0(r12)")
	print("\tlwz	r2, 4(r12)")
	print("\tmtctr	r0")
	print("\tbctrl")
	print("\tld	r2, 112(r1)")
	print("\taddi	r1, r1, 128")
	print("\tld	r0, 16(r1)")
	print("\tmtlr	r0")
	print("\tblr")
	print("")
	print("\t.align 3")
	print("\t.section \".opd\", \"aw\"")
	print("\t.globl " + name)
	print(name + ":")
	print("\t.quad __" + name + ", .TOC.@tocbase, 0")

def generate_asm(lib_name, library):
	functions = library["functions"]

	generate_lib_resident(lib_name)
	print("")

	generate_lib_stub(lib_name)
	print("")

	for func_name in functions:
		generate_fstub(func_name)
		print("")

	print("\t.section \".rodata.sceFNID\", \"a\"")
	print(lib_name + ":")
	for func_name in functions:
		nid = functions[func_name]
		print(func_name + "_fnid:")
		print("\t.long " + "0x{:08X}".format(nid))
	print("")

	print("\t.section \".data.sceFStub." + lib_name + "\", \"aw\"")
	print("sceFStub:")
	for func_name in functions:
		print(func_name + "_stub:")
		print("\t.long __" + func_name)
	print("")

def process_file(filename):
	with open(filename, 'r') as f:
		db = yaml.safe_load(f)
		modules = db["modules"]
		for mod_name in modules:
			libraries = modules[mod_name]["libraries"]
			for lib_name in libraries:
				generate_asm(lib_name, libraries[lib_name])

if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage()
	else:
		process_file(sys.argv[1])
