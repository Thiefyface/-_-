#!/usr/bin/env python
import sys 

# Patch files can be genned with `hexdump -C <file>` or `hexedit`
# Example patch_file format: (only patches 0x1d30-0x1d40, 0x2de0-0x2E00)
# 00001D30   69 6E 00 00  00 00 00 00  00 00 00 00  00 00 00 00  in..............
# --------
# 00002DE0   00 FF FF FF  00 00 00 00  00 00 00 00  00 00 00 00  ................
# 00002DF0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................

def main():

    if len(sys.argv) < 3:
        print("[x.x] Usage: %s <legit_file> <patch_file>")
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
        line_sections = filter(None,line.split()) 
        try:
            address = int(line_sections[0],16)
        except:
            if line.startswith("-"):
                continue
                 
        hex_bytes = line_sections[1:-1]

        hex_buff = "" 
        for hbyte in hex_bytes:
            try:    
                hex_buff+=chr(int(hbyte,16)) 
            except:
                pass

        patch_dict[address] = hex_buff[:] 

    print("[^-^] Patches read in, applying %d lines worht of patchies."%len(patch_dict))

    for addr in patch_dict.keys():
        patch_len = len(patch_dict[addr])
        legit_buf = legit_buf[:addr] + patch_dict[addr] + legit_buf[addr+patch_len:] 
        print("[>_>] Wrote 0x%lx bytes to offset 0x%lx"%(patch_len,addr)) 

    print("[._.] Writing patched file!!")
    with open("%s.patched"%sys.argv[1],"wb") as f:
        f.write(legit_buf)
    print("[^_^] Done!!! <3")


if __name__ == "__main__":
    main()
