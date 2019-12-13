#!/usr/bin/env python3

# https://blahcat.github.io/2018/03/11/fuzzing-arbitrary-functions-in-elf-binaries/
import lief
import sys

if len(sys.argv) < 3:
    print("[x.x] Usage: %s <binary> <funcs.txt>" % sys.argv[0])
    print("(where file => func_name|addr\\nfunc_name2|addr2....)")
    sys.exit()

try:
    elf = lief.parse(sys.argv[1])
except:
    print("[x.x] Unable to open %s"%sys.argv[1])
    sys.exit()

func_list = []

with open(sys.argv[2],"rb") as f:
    for l in f.split("\n"):
        func_list.append(l.split("|")) 

    print("[F.F] Func list => %s"%str(func_list))

for func,addr in func_list:
    print("exporting %s:0x%lx"%(func,int(addr.rstrip(),16)))
    ret = elf.add_exported_function(int(addr.rstrip(),16),func)
    print(ret)

#elf.add_exported_function(0x5352b0,"main")

outfile = sys.argv[1] + ".so"
try:
    print("[!_!] Writing to %s"%outfile)
    elf.write(outfile)
except:
    print("[x.x] Unable to write to %s")
    
from ctypes import *
x= CDLL("./%s"%outfile)
print("[^_^] All done!") 
