# encoding: utf-8


from binascii import *
import sys


def str2pushdata(string):
    result = []
    l = len(string) % 4
    string += '\0' * (4 - l)
    for i in range(0, len(string), 4):
        a = string[i:i+4]
        result.append("push 0x{}".format(b2a_hex(a[::-1])))
    return result
        

if __name__ == "__main__":
    result = str2pushdata(string=sys.argv[1])
    pop = []
    for i in result[::-1]:
        print(i)
        pop.append("pop ebx")
    for i in pop:
        print(i)
