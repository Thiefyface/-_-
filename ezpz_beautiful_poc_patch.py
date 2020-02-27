#!/usr/bin/env python
import sys 

# Patch files can be genned with `hexdump -C <file>` or `hexedit`
# Example patch_file format: (only patches 0x1d30-0x1d40, 0x2de0-0x2E00)
# 00001D30   69 6E 00 00  00 00 00 00  00 00 00 00  00 00 00 00  in..............
# --------
# 00002DE0   00 FF FF FF  00 00 00 00  00 00 00 00  00 00 00 00  ................
# 00002DF0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................

# comments via '//' or '#' at front of line

# For groups of bytes use:
# 22001010 ! "\x00\x00\x00\x01" * 0x1000

def main():

    if len(sys.argv) < 3:
        print("[x.x] Usage: %s <legit_file> <patch_file>"%sys.argv[0])
        sys.exit()

    legit_buf = ""
    patch_buf = ""
    patch_dict = {}

    try:
        with open(sys.argv[1],"rb") as f:
            legit_buf = f.read()
        with open(sys.argv[2],"rb") as f:
            patch_buf = f.read()
    except Exception as e:
        print("[x.x] %s"%str(e))
        sys.exit()

    for line in patch_buf.split("\n"):
        line_section = filter(None,line.split()) 
        #print line_sections
        try:
            address = int(line_section[0],16)
        except:
            if line.startswith("-") or line.startswith("#") or line.startswith("//"):
                continue
            else:
                continue

        # do a check for special commands 
        if line_section[1] == "!":
            num = 0x0
            # expected format is ! "<bytestr>" * <num> 
            try:
                bytestr = line_section[2][:]
                if bytestr.startswith('"') and bytestr.endswith('"'):
                    bytestr = bytestr[1:-1]

                bytebuf = ""
                if "\\x" in bytestr:
                    bytestr = bytestr.replace("\\x","")

                
                try:
                    for i in range(0,len(bytestr),2):
                        bytebuf+=chr(int(bytestr[i:i+2],16)) 
                except Exception as e:
                    # i guess just try the unescaped bytes
                    print str(e)
                    bytebuf = line_section[2] 

                op = line_section[3]
            except:
                print("[x.x] INvalid operation line, exiting: %s"%line_section)
                sys.exit() 
            try:
                num = int(line_section[4],10)
            except:
                try:
                    num = int(line_section[4],16)
                except:
                    print("[x.x] Invalid operation line number, exiting: %s"%line_section[4])
                    sys.exit()

            if op == "*":
                hex_buff = bytebuf*num 
            else:
                print("[?.?] What sort of operation is that? jeeze")
                sys.exit()

        else: 
            hex_bytes = line_section[1:-1]

            hex_buff = "" 
            for hbyte in hex_bytes:
                try:    
                    hex_buff+=chr(int(hbyte,16)) 
                except:
                    pass

        patch_dict[address] = hex_buff[:] 

    print("[^-^] Patches read in, applying %d lines worht of patchies."%len(patch_dict))

    for addr in patch_dict.keys():
        #print "[.x.] %s: %s"%(patch_dict,patch_dict[addr])
        patch_len = len(patch_dict[addr])
        legit_buf = legit_buf[:addr] + patch_dict[addr] + legit_buf[addr+patch_len:] 
        print("[>_>] Wrote 0x%lx bytes to offset 0x%lx"%(patch_len,addr)) 

    print("[._.] Writing patched file!!")
    with open("%s.patched"%sys.argv[1],"wb") as f:
        f.write(legit_buf)
    print("[^_^] Done!!! <3")






if __name__ == "__main__":
    main()
