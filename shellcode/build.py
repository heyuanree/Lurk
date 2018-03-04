# coding=utf-8

import os
import sys
import logger
from subprocess import Popen


def locate(src_file, dir=os.getcwd()):
    for root, dirs, files in os.walk(dir):
        for name in files:
            if src_file == name:
                return root
    return None


def build(name):
    """
    :param name: name should be no extension
    :return: bin_name
    """
    location = locate("{}.asm".format(name))
    bin_name = name + '.bin'
    if location:
        src_input = os.path.normpath(os.path.join(location, name))
        bin_output = os.path.normpath(os.path.join(os.getcwd() + '\\shellcode\\tmp', name))
        p = Popen(["nasm", "-f bin", "-O3", "-o {}.bin".format(bin_output), "{}.asm".format(src_input)])
        p.wait()
    return bin_name


def get_file_content(name):
    root = locate(name, dir=os.getcwd())
    if root:
        with open(root + '\\{}'.format(name), 'rb') as f:
            file_contect = f.read()
    else:
        logger.error("Cannot find file {}".format(name))
        sys.exit(1)
    return file_contect


def get_shellcode_len(name):
    shellcode_len = len(get_file_content(name))
    return shellcode_len