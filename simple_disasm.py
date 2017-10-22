#!/usr/bin/env python
from capstone import *
import string
import sys
import os

def main():
    print "[^_^] Simple Disassembler"

    sc = ""
    shellcode = ""

    try:
        if os.path.isfile(sys.argv[1]):
            with open(sys.argv[1],"rb") as f:
                sc = f.read()
                print "GOT SC: 0x%x" % len(sc)
        else:
            sc = sys.argv[1]
    except Exception as e:
        import traceback
        print "[x.x] Usage: %s <shellcode> (e.g. \\x11\\x22\\x33... or a raw file)"
        print traceback.format_exc()
        sys.exit()

    if all(char in string.printable for char in sc): #not a raw buffer
        try:
            shellcode = ''.join([chr(int(i,16)) for i in filter(None,sc.split("\\x"))])
        except Exception as e: # maybe just raw
            print e
            try:
                for i in range(0,len(sc),2):
                    shellcode+=chr(int(sys.argv[1][i:i+2],16))
            except TypeError:
                pass

    buf = ""
    md = Cs(CS_ARCH_X86,CS_MODE_64)
    for i in md.disasm(sc,0x0):
        line = ""
        b = "\\x"+"\\x".join(["%02x"%x for x in i.bytes])
        line += "0x%04x |  %s %s"%(i.address,i.mnemonic,i.op_str)
        line += " "*(50-len(line))
        line += b
        line += "\n"
        buf += line
    print buf

if __name__ == "__main__":
    main()
