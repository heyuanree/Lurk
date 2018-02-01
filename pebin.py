# coding:utf-8

import sys
import os
import subprocess


class pebin():
    """
    PE binary class.
    """
    def __init__(self, FILE, OUTPUT, APPEND_SECTION, SHELLCODE, LHOST, LPORT, INJECT):
        self.FILE = FILE
        self.OUTPUT = OUTPUT
        self.APPEND_SECTION = APPEND_SECTION
        self.SHELLCODE = SHELLCODE,
        self.LHOST = LHOST
        self.LPORT = LPORT

    def run_this(self):
        if self.APPEND_SECTION is True:
            self.append_section()
            sys.exit()

    def append_section(self):
        pass
