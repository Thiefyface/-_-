#!/usr/bin/env python
from capstone import *
import string
import sys
import os

def main():
    print "[^_^] Lil'Disassembler"

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
        sc = sc.replace("\\x","")
        try:
            for i in range(0,len(sc),2):
                if sc[i:i+2]:
                    shellcode+=chr(int(sc[i:i+2],16))
        except TypeError as e:
            print e
            pass
    else:
        shellcode = sc

    buf = ""
    md = Cs(CS_ARCH_X86,CS_MODE_64)
    for i in md.disasm(shellcode,0x0):
        line = ""
        b = "\\x"+"\\x".join(["%02x"%x for x in i.bytes])
        line += "0x%04x |  %s %s"%(i.address,i.mnemonic,i.op_str)
        line += " "*(50-len(line))
        line += b
        line += "\n"
        buf += line

    if buf:
        print buf
    else:
        print "[;_;] No parsable instructions gefunden."

if __name__ == "__main__":
    main()
