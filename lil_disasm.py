#!/usr/bin/env python
from capstone import *
import string
import sys
import os

def dump_shellcode(filename,filename2="",match_list=[]):

    buf = ""

    shellcode = read_bin(filename)

    if filename2:
        shellcode2 = read_bin(filename2)
        if len(shellcode) < len(shellcode2):
            # swap so we know the order
            tmp = shellcode
            shellcode = shellcode2
            shellcode2 = tmp
            
    md = Cs(CS_ARCH_X86,CS_MODE_64)
    disasm = md.disasm(shellcode,0x0)

    for i in disasm:
        matched = False
        line = ""
        b = "\\x"+"\\x".join(["%02x"%x for x in i.bytes])
        line += "0x%04x |  %s %s"%(i.address,i.mnemonic,i.op_str)

        for match in match_list:
            lb = match[0]
            ub = lb+match[2]           
            # test for match bounds
            if (lb <= i.address) and (ub >= i.address+i.size):
                #match 
                line = GREEN + line
                line += " "*(50-len(line))
                line += b
                line += CLEAR
                matched = True
                break

        if filename2 and not matched:
            line = YELLOW + line + CLEAR
                    
 
        if not filename2: 
            line += " "*(50-len(line))
            line += b

        line += "\n"
        buf += line

    print buf
    if filename2:
        disasm2 = md.disasm(shellcode2,0x0) 

        for istr in disasm2:
            line = ""
            b = "\\x"+"\\x".join(["%02x"%x for x in i.bytes])
            line += "0x%04x |  %s %s"%(i.address,i.mnemonic,i.op_str)
            if not filename2: 
                line += " "*(50-len(line))
                line += b
            line += "\n"
            buf += line

    if len(sys.argv) == 2: 
        print buf

    if buf:
        return buf
    else:
        output("[;_;] No parsable instructions gefunden.",YELLOW)



def read_bin(binary_file,verbose=False):
    shellcode = ""
    try:
        if os.path.isfile(binary_file):
            with open(binary_file,"rb") as f:
                sc = f.read()
                if verbose:
                    output("Loaded %s, len:0x%x" % (binary_file,len(sc)),CYAN)
        else:
            sc = sys.argv[1]
    except Exception as e:
        import traceback
        output("[x.x] Usage: %s <shellcode> (e.g. \\x11\\x22\\x33... or a raw file)",YELLOW)
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

    return shellcode


def diff_raw_shellcode(buf1,buf2):
    sbuf,lbuf = (buf1,buf2) if len(buf1) < len(buf2) else (buf2,buf1)
    
    lb = 0
    ub = len(sbuf)
    sbuf_index = ub
    lbuf_index = -1
    match_list = []

    while lb != ub:
        match_str = sbuf[lb:sbuf_index]
        #print "LenMatch: 0x%x"%len(match_str)
        if len(match_str) < 2:
            # ignore 1 byte matches
            # no match, choke up on sbuf
            lb+=1 
            sbuf_index = ub
            continue

        if match_str in lbuf:
            lbuf_index = lbuf.find(match_str)
        
            # (index in sbuf, index in lbuf, len)
            output("[^_^] Found match: (0x%x,0x%x),len 0x%x"%(lb,lbuf_index,len(match_str)))
            match_list.append((lbuf_index,lb,len(match_str))) 
            lb = sbuf_index
            sbuf_index = ub         

        sbuf_index -= 1
            

    return match_list 


def main():
    if len(sys.argv) == 2:
        dump_shellcode(sys.argv[1]) 

    if len(sys.argv) == 3:
        buf1 = read_bin(sys.argv[1],verbose=True)
        buf2 = read_bin(sys.argv[2],verbose=True)
        diff_list = diff_raw_shellcode(buf1,buf2)
        print "Dumping shellcode"
        dump_shellcode(sys.argv[1],sys.argv[2],diff_list)
    
RED='\033[31m'
ORANGE='\033[91m'
GREEN='\033[92m'
LIME='\033[99m'
YELLOW='\033[93m'
BLUE='\033[94m'
PURPLE='\033[95m'
CYAN='\033[96m'
CLEAR='\033[00m' 

def output(inp,color=None):
    if color:
        sys.__stdout__.write("%s%s%s\n" % (color,str(inp),CLEAR)) 
        sys.__stdout__.flush()
    else:
        sys.__stdout__.write(str(inp)+"\n")
        sys.__stdout__.flush()

if __name__ == "__main__":
    output("[^_^] Lil'Disassembler",GREEN)

    if len(sys.argv) < 2:
        output("[x-x] Needs more args, yo.",YELLOW)
        output("[x.x] Usage: %s <shellcode> (e.g. \\x11\\x22\\x33... or a raw file)",YELLOW)
        sys.exit()

    main()

