#!/usr/bin/python
import sys

def main():
    datadict = {}
    lastaddr = 0x0
    inp = ""
    out = b""
    if len(sys.argv) < 2:
        print('[x.x] Usage: %s <in.hex> <out.bin>')
        return
    
    try:
        with open(sys.argv[1],"r") as f:
            inp = f.read().split('\n')
    except:
        print("[x.x] unable to read input file, rip.")
        return
    
    outfile = None
    try:
        outfile = open(sys.argv[2],"wb")
    except:
        try:
            outfile = open("%s.bin"%sys.argv[1],"wb")
        except Exception as e:
            print(e)
            print("[x.x] Can't write anything, exiting")
            return
            
    
    for line in inp:
        if len(line) <= 0x2:
            continue

        sep1 = line.find("  ")
        sep2 = line.rfind("  ")

        addr = int(line[:sep1],16) 
        blist = line[sep1:sep2].split()
        if not len(blist):
            continue
    
        bytestr = b''
        for b in blist:
            bytestr+=chr(int(b,16)).encode("latin-1")

           
        #print(blist)
        if len(bytestr):
            datadict[addr] = bytestr
            
            difference = addr - (lastaddr + len(datadict[lastaddr]))
            #print("[>_>] difference: 0x%lx\n"%difference)
            outfile.write(b'\x00'*difference)
            outfile.write(bytestr)
            lastaddr = addr 
       
        
    outfile.close()
    #print(datadict)

if __name__ == "__main__":
    main()

