#!/usr/bin/env python
from capstone import *
import sys

def main():
    print "[^_^] Simple Disassembler"
    if "x" in sys.argv[1]:
        try:
            shellcode = ''.join([chr(int(i,16)) for i in filter(None,sys.argv[1].split("\\x"))])
        except Exception as e:
            print e
            print "[x.x] Usage: %s <shellcode> (e.g. \\x11\\x22\\x33...)"
            sys.exit() 
    else:
        shellcode = ""
        for i in range(0,len(sys.argv[1]),2):
            try:
                shellcode+=chr(int(sys.argv[1][i:i+2],16))
            except TypeError:
                pass

    buf = ""
    md = Cs(CS_ARCH_X86,CS_MODE_64)
    for i in md.disasm(shellcode,0x0):
        line = ""
        b = "\\x"+"\\x".join(["%02x"%x for x in i.bytes])
        line += "0x%04x |  %s %s"%(i.address,i.mnemonic,i.op_str)
        line += " "*(40-len(line))
        line += b
        line += "\n"
        buf += line
    print buf
   
if __name__ == "__main__":
    main()
