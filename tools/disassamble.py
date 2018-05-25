# coding: utf-8

from capstone import *
import sys

def read_rawdata(file_name):
    with open(file_name, 'rb') as f:
        raw_data = f.read()
    return raw_data

def disasm(raw_data):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = md.disasm(raw_data, 0)
    return code

def show_code(code):
    for _code in code:
        print("0x{0:x}\t{1:s}\t{2:s}".format(_code.address, _code.mnemonic, _code.op_str))

if __name__ == '__main__':
    useage = "disasmable.py <file>"
    if sys.argv[1]:
        raw_data = read_rawdata(sys.argv[1])
        code = disasm(raw_data)
        show_code(code)
    else:
        print(useage)