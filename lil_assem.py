#!/usr/bin/env python
from keystone import *
import struct
import sys
import os

verbose = True
class Assembler():
    
    def __init__(self): 
        self.ks_mode = KS_MODE_64
        self.ks = Ks(KS_ARCH_X86,self.ks_mode)
        self.asm_buffer = []   # hold raw opcodes
        self.len = 0
        self.instr_count = 0
        self.encoded_buffer = []
        self.baseaddr = 0
        self.labels = {} 
        self.dbgcmds = []

    def encode_shellcode(self,badchar="",xorkey=0x0):
        char_counter = "".join([chr(x) for x in range(1,256)])

        if xorkey == 0x0:
            xor_key = 0x30
        else:
            xor_key = xorkey
        #  attempt to find a char not in the shellcode

        if badchar: 
            for char in self.asm_buffer:
                if char in char_counter: 
                    char_counter = char_counter.replace(char,"") 
            if len(char_counter) > 0:   # ideally use random char from leftovers 
                xor_key = ord(badchar) ^ ord(char_counter[0]) 
                print "[!.!] Xoring with key 0x%02x"%xor_key
       
        # create encoded version.
        for char in self.asm_buffer:
            self.encoded_buffer.append(chr((ord(char) ^ xor_key))) 


        # create decoder stub 
        stub = list(self.get_xor_decoder_stub(xor_key))
        enc = self.encoded_buffer
        #print stub
        #print enc
    
        return stub + enc

    def get_xor_decoder_stub(self,xor_key):
        placeholder = "\x30\x30\x30\x30"
        xorfile = os.path.abspath(os.path.join(__file__,"../xorstub.txt"))
        # 0x1f bytes total.
        # 0x12 for loop
        # todo, make this more efficient...
        old_asm = self.asm_buffer[:]
        xor_stub = "".join([x for x in self.import_file(xorfile,raw=True)]) 

        self.len+=len(old_asm)
    
        # num bytes to xor          # 2 bytes 
        xor_stub = xor_stub.replace("$$$$",struct.pack("<I",len(old_asm)+0x8)) 
        xor_key = chr(xor_key)*4
        xor_stub = xor_stub.replace(placeholder,xor_key) 

        print "[^_^] Xor key: %s" % repr(xor_key)
        
        return xor_stub


    def import_file(self,filename,raw=False):
        raw_bytes = []
        self.asm_buffer = ""

        with open(filename,"r") as f:
            inp = f.read() 
        # normalize
        instrs = inp.split("\n") 
        for i in range(0,len(instrs)):
            if ';' in instrs[i]:
                instrs[i] = instrs[i][:instrs[i].find(";")] # strip comments
            instrs[i] = instrs[i].rstrip()
            
        instrs = filter(None,instrs)

        for i in range(0,len(instrs)): 
            if instrs[i][0] == "!" and instrs[i][-1] == "!":
                # add raw bytes
                tmp = instrs[i][1:-1]
                while "\\x" in tmp:                
                    target = tmp.find("\\x")
                    byte = tmp[target:target+4] 
                    tmp = tmp.replace(byte,chr(int(byte[2:],16))) 

                print repr(tmp)
                self.asm_buffer += tmp 
            elif instrs[i][0] == "#": 
                # add label
                self.labels[instrs[i][1:]] = self.baseaddr+len(self.asm_buffer)  
            elif instrs[i][0] == "$":
                self.dbgcmds.append(instrs[i][1:])

            else:
                # add normal bytes

                if "@" in instrs[i]:
                    # substute label for actual addr. What if we need to jump down???...  
                    newinst,label = instrs[i].split("@")                            
                    try:
                        addr = self.labels[label] 
                        reladdr = addr - (self.baseaddr + len(self.asm_buffer)) 
                        newinst += hex(reladdr)
                        instrs[i] = newinst
                    except Exception as e:
                        print "Couldn't reassign label: %s"%instrs[i]
                        print e 
                        sys.exit()

                try:
                    tmp_byte,_ = self.ks.asm(instrs[i])          
                except:
                    print "[x.x] Unable to assemble on string: %s"%instrs[i]
                    sys.exit
                self.instr_count += 1
                if tmp_byte:
                    self.asm_buffer += ''.join([chr(c) for c in tmp_byte])
                else:
                    print "Unable to assmble %s" % (instrs[i])


        self.len = len(self.asm_buffer)
        print "#[^_^] Assembled 0x%lx instr to 0x%lx bytes!" % (self.instr_count,self.len)
        if raw:
            return self.asm_buffer  
        else:
            return "\\x"+"\\x".join(["%02x"%ord(c) for c in self.asm_buffer])

    def get_shellcode(self):
        if self.asm_buffer:
            print self.asm_buffer 
            return "".join([x for x in self.asm_buffer])
        return ""
             
 
    def get_gdb_cmds(self,buf="",address=0x0,mode="x64"):
        #self.ks_mode = KS_MODE_64
        #self.ks = Ks(KS_ARCH_X86,self.ks_mode)
        width = 4 # can only write in 4 byte chunks.
        ptr = address 
        if not buf:
            buf = self.asm_buffer 

        ret = ""
        kirby_load = ["<(^_^)>","(>o.o)>","(^-_-^)",
                      "<('~'^)","<(c.c<)","<(^_^v)",
                      "(v._.v)","(v~.~)>","(>x.x)>"]
        
        for i in range(0,self.len,width):
            try:
                val = "0x%08x" % int(struct.unpack("<I",''.join(buf[i:i+width]))[0])
            except:
                print self.asm_buffer[i:i+width]
                break
            ret += "set *0x%lx=%s\n" % (ptr,str(val)) 
            # loading indicator
            if i == 0:
                ret += "printf \"%s\"\n" % (kirby_load[i%len(kirby_load)])
            else:
                ret+= "printf \"%s%s\"\n" % (kirby_load[i%len(kirby_load)],"\\b"*7) 
            ptr += width
         
        ret += "x/%di 0x%lx\n"%(self.instr_count,address) 
        # add dbgcmds if any.        
        for cmd in self.dbgcmds:
            ret+="%s\n"%cmd

        return ret 


if __name__ == "__main__":
    a = Assembler()
    try:
        a.baseaddr = int(sys.argv[2],0x10)
    except:
        a.baseaddr = 0x0

    sc_buff = a.import_file(sys.argv[1])
       
    outpath = os.path.dirname(os.path.abspath(__file__))

    if "gdb" in sys.argv: 
        with open(os.path.join(outpath,"gdbcmd.txt"),"w") as f: 
            f.write(a.get_gdb_cmds(address=a.baseaddr))

    if "raw" in sys.argv:
        with open(os.path.join(outpath,"sc.txt"),"w") as f:
            f.write(sc_buff) 

    if "encode" in sys.argv:      
        with open(os.path.join(outpath,"encoded.txt"),"w") as f:
            encoded = a.encode_shellcode(badchar="\xff")
            buf = "\\x" + '\\x'.join(["%02x"%ord(c) for c in encoded ])
            f.write(buf)
            print "[>-<] Encoded buff written to encoded.txt"
        with open(os.path.join(outpath,"gdbcmd.txt"),"w") as f:
            print "[>->] Encoded gdb written to gdbcmd.txt"
            f.write(a.get_gdb_cmds(encoded,address=a.baseaddr))
            
    else: 
        print sc_buff
        print "[^_^] Label entries:"
        for entry in a.labels:
            print "%s | 0x%lx" % (entry,a.labels[entry]) 

        
