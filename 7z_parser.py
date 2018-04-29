#!/usr/bin/env 
import sys
import struct


def main():

    _7zbuff = ""

    with open(sys.argv[1],'rb') as f:
        _7zbuff = f.read()

    '''
    0000000000: 37 7A BC AF 27 1C 00 04   5B 38 BE F9 59 0E 00 00 
    0000000010: 00 00 00 00 23 00 00 00   00 00 00 00 7A 63 68 FD 
    0000000020: 00 21 16 89 6C 71 3D AB   7D 89 E6 3C 2E BE 60 24 

    00: 6 bytes: 37 7A BC AF 27 1C        - Signature 
    06: 2 bytes: 00 04                    - Format version
    08: 4 bytes: 5B 38 BE F9              - CRC of the following 12 bytes
    0C: 8 bytes: 59 0E 00 00 00 00 00 00  - relative offset of End Header
    14: 8 bytes: 23 00 00 00 00 00 00 00  - the length of End Header
    1C: 4 bytes: 7A 63 68 FD              - CRC of the End Header
    '''

    print "=================Begin 7z Header parsing (0x0->0x20)======================"
    signature = _7zbuff[0x0:0x6] 
    if signature != "\x37\x7a\xbc\xaf\x27\x1c":
        print "Invalid signature: %s, expected %s"%(repr(signature),repr("\x37\x7a\xbc\xaf\x27\x1c"))
        sys.exit()
    
    version = struct.unpack(">H",_7zbuff[0x6:0x8])[0]
    header_crc = struct.unpack("<I",_7zbuff[8:0xC])[0]
    tail_addr = struct.unpack("<Q",_7zbuff[0xC:0x14])[0] + 0x20
    tail_size = struct.unpack("<Q",_7zbuff[0x14:0x1C])[0]
    tail_crc = struct.unpack("<I",_7zbuff[0x1C:0x20])[0]
    
    print "Signature      : %s" % repr(signature) 
    print "Version        : 0x%x" % version 
    print "HeaderCrc      : 0x%x" % header_crc
    print "TailAddr       : 0x%lx" % tail_addr
    print "TailSize       : 0x%lx" % tail_size 
    print "TailCrC        : 0x%x" % tail_crc


    tail = _7zbuff[tail_addr:tail_addr+tail_size]
    head = _7zbuff[0x20:]
    '''
    End header
    002457e0  17 06 e0 20 4f 24 01 09   88 a0 00 07 0b 01 00 02      
    002457f0  24 06 f1 07 01 0a 53 07   1f 03 65 f5 9f 71 0b f1     
    00245800  23 03 01 01 05 5d 00 40   00 00 01 00 0c 88 98 b3      
    00245810  82 0a 01 5d 29 c8 39 00   00                           

    +0x0 : '\x17' => "kEncodedHeader"
    +0x1 : '\x06' => "kPackInfo" 
    +0x2 : '\xe0' => ReadNumber bit mask for amt of bytes to read in the next field. 
                    (e.g. 0x80=>1 byte.  0xc0=>2 bytes, 0xe0=>3 bytes, 0xf0 =>4 bytes.... 8 bytes) 
                                                       (0x88 => 1 byte mask, 0x8f => lower 1 byte)
    +0x3 : Offset next header   '0x244f40' 
    +0x6 : '\x01' => # of pack streams 
    +0x7 : '\x09' => "kSize"
    +0x8 : '\x88' => ReadNumber Mask. (0x80 | next field)
    +0x9 : '\xa0' => kSize | 0x80 => 0xa0.  0x80 => minimum. 
    +0xa : '\x00' => "kEnd" 
    +0xb : '\x07' => "kUnpackInfo"
    +0xC : '\x0b' => "kFolder"
    +0xD : '\x01' => Readmask. 
    '''
    # first it reads an ID. !=kHeader && !=kEncodedHeader => error. 
    hbyte = ord(tail[0])
    if hbyte != 0x01 and hbyte != 0x17: 
        print "Error: tail[0] != kHeader(0x01)/kEncodedHeader(0x17). Val:0x%02x" %hbyte
        sys.exit(-1)
    print "============Begin Tail header parsing (0x%lx->0x%lx)=================" %(tail_addr,tail_addr+tail_size)
    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])

    hptr = 0x0
    tptr = 0x1 # keep track of where we are in the tail header  

    if hbyte == 0x17: # yayyy, do Read/Decode.
        
        '''
        RESULT result = ReadAndDecodePackedStreams(
            EXTERNAL_CODECS_LOC_VARS
            db.ArcInfo.StartPositionAfterHeader, => 0x20 after first headers
            db.ArcInfo.DataStartPosition2,       => Guessing this starts at 0x0     
            dataVector //   =>???                  |and is soon read in. 
            _7Z_DECODER_CRYPRO_VARS
            );
        => ReadStreamsInfo(NULL,dataOffset,folders,unpackSizes,digests)
        '''
        hbyte,bread = read_number(tail[tptr:tptr+9])  
        print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
        tptr+=bread 

        if hbyte == 0x6: #kPackInfo
            dataOffset,bread = read_number(tail[tptr:tptr+9])
            print "dataOffset     : 0x%lx" % dataOffset 
            tptr+=bread
            
            numPackStreams,bread = read_number(tail[tptr:tptr+9])
            print "numPackStreams : 0x%02x" % numPackStreams 
            tptr+=bread

            #packinfo = ReadPackInfo()
            while True:
                hbyte,bread = read_number(tail[tptr:tptr+9])
                tptr+=bread
                if hbyte == 0x9: #(kSize)
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    break

            for i in range(0,numPackStreams): 
                packSize,bread = read_number(tail[tptr:tptr+9])
                tptr+=bread
                print "packSize[%d]    : 0x%02x" % (i,packSize)

            while True:
                hbyte,bread = read_number(tail[tptr:tptr+9])
                tptr+=bread
                if hbyte == 0x0: #(kEnd)
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    break
                elif hbyte == 0xa: #(kCRC)
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    print "implimient crc read, lol"
                else:
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    print "impliment skip data"
    
                 

            hbyte,bread = read_number(tail[tptr:tptr+9])
            tptr+=bread
            print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])

        
        #unpackinfo = ReadUnpackInfo()
        if hbyte == 0x7: #kUnpackInfo 
            dataOffset+=0x20
            data = _7zbuff[dataOffset:]
            dptr = 0x0
             
            
            #print "\\x" + "\\x".join("%02x"%ord(s) for s in data[0:10])

            numCodersOutStreams = 0x0

            while True:
                hbyte,bread = read_number(tail[tptr:tptr+9]) 
                tptr+=bread
                if hbyte == 0xb: #(kFolder)
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    break
            numFolders,bread = read_number(tail[tptr:tptr+9])
            tptr+=bread
            print "numFolders     : 0x%02x" % numFolders 
    
            useless,bread = read_number(tail[tptr:tptr+9]) 
            tptr+=bread
            print "Useless read   : 0x%02x" % useless

            for x in range(0,numFolders):
                numCoders,bread = read_number(tail[tptr:tptr+9]) 
                tptr+=bread
                print "numCoders      : 0x%02x" % numCoders
                if numCoders > 64 or numCoders == 0x0:
                    print "Invalid numCoder:0x%x (> 64)" % numCoders
                    sys.exit()

                coderID = []
                for i in range(0,numCoders):        
                    mainByte = ord(tail[tptr])
                    tptr+=1
                    print "mainByte       : 0x%02x" % mainByte
                    if mainByte &0xC0 != 0x0:
                        print "Invalid mainByte:0x%x " % mainByte
                        sys.exit()
        
                    idSize = mainByte&0xF
                    if idSize > 8:
                        print "Invalid idsize:0x%x (>0x8)" % idSize
                        sys.exit()
        
                 
                    if idSize == 1:
                        _id = struct.unpack("B",tail[tptr:tptr+idSize])[0] 
                    elif idSize == 2:
                        _id = struct.unpack(">H",tail[tptr:tptr+idSize])[0] 
                    elif idSize == 3:
                        _id = struct.unpack(">I","\x00" + tail[tptr:tptr+idSize])[0] 
                    elif idSize == 4:
                        _id = struct.unpack(">I",tail[tptr:tptr+idSize])[0] 
                    elif idSize == 8:
                        _id = struct.unpack(">Q",tail[tptr:tptr+idSize])[0] 
                            
                    coderID.append(_id)
                
                    # skip over idSize
                    tptr+=idSize
                    
                    print "CoderID[%d]     : 0x%lx : (%s)" % (i,_id,cDict[_id]) 

                    if (mainByte & 0x10) != 0:
                        coderInStreams,bread =read_number(tail[tptr:tptr+9]) 
                        tptr+=bread
                        if coderInStreams > 64:
                            print "Invalid coderInStreams:%d"%coderInStreams
                            sys.exit()
                        _,bread =read_number(tail[tptr:tptr+9]) 
                        tptr+=bread
                        if _ != 1:
                            print "Invalid post coderInStream read:%d"%_
                            sys.exit()
            
                    if (mainByte & 0x20) != 0:
                        propsSize,bread =read_number(tail[tptr:tptr+9]) 
                        tptr+=bread
                        print "propsSize      : 0x%02x" % (propsSize) 
        
                        #if _id == 0x21 & propsSize == 1: #"k_LZMA2"
                        if _id == 0x30101 and propsSize == 5: #"k_LZMA"
                            dicSize = struct.unpack("<I",tail[tptr+1:tptr+5])[0]
                            print "dicSize        : 0x%02x" % (dicSize) 
                        
                    #skipzies
                    #tptr+=propsSize

                        if _id == 0x6f10701: # k_AES
                            # parse out the props 
                            # NumCyclesPower,saltSize,ivSize,IV
                            b0 = ord(tail[tptr])
                            tptr+=1
                            b1 = ord(tail[tptr])
                            tptr+=1

                            NumCyclesPower = b0 & 0x3F
                            print "NumCyclesPower : 0x%02x" % (NumCyclesPower) 
                            saltSize = ((b0 >> 7) & 1) + (b1 >> 4) 
                            print "saltSize       : 0x%02x" % (saltSize) 
                            ivSize = ((b0 >> 6) & 1 ) + (b1 & 0xF)  
                            print "ivSize         : 0x%02x" % (ivSize) 

                            if saltSize > 0:
                                Salt = struct.unpack("B"*saltSize,tail[tptr:tptr+saltSize]) 
                                tptr+=saltSize
                                print "Salt          %08x" % Salt 
        
                            #print "\\x" + "\\x".join("%02x"%ord(x) for x in tail[tptr:tptr+ivSize])
                            #IV,bread = struct.unpack("<Q",) 
                            IV = tail[tptr:tptr+ivSize] +"\x00\x00\x00\x00\x00\x00\x00\x00"
                            tptr+=ivSize
                            print "IV             : 0x%08x" % struct.unpack(">Q",IV[0:8]) 
                      
            
                # end numCodersLoop 
                numInStreams = numCoders
                if numCoders == 1 and numInStreams == 1:
                    indexOfMainStream = 0
                    numPackStreams = 1
                    numBonds = 0
                else:
                    numBonds = numCoders -1 

                    for i in range(0,numBonds):
                        bIndex,bread =read_number(tail[tptr:tptr+9]) 
                        tptr+=bread
                        print "bIndex         : 0x%02x" % (bIndex) 
                
                        cIndex,bread =read_number(tail[tptr:tptr+9]) 
                        tptr+=bread
                        print "cIndex         : 0x%02x" % (cIndex) 


                StreamUsed = []
                numPackStreams = numInStreams-numBonds
                if (numPackStreams != 1):
                    for i in range(0,numPackStreams):
                        sIndex,bread =read_number(tail[tptr:tptr+9]) 
                        tptr+=bread
                        print "sIndex      : 0x%02x" % (cIndex) 
                        StreamUsed.append(sIndex)

        
                numCodersOutStreams+=numCoders
                
                # end numFolders loop

            while True:
                hbyte,bread = read_number(tail[tptr:tptr+9])
                tptr+=bread
                if hbyte == 0xC: #(kCodersUnpackSize)
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    break


            CoderUnpackSizes = []
            for i in range(0,numCodersOutStreams):
                size,bread = read_number(tail[tptr:tptr+9])
                tptr+=bread
                CoderUnpackSizes.append(size) 
            print "CoderUnpackSize: %s" % str(CoderUnpackSizes)
            
            while True:
                hbyte,bread = read_number(tail[tptr:tptr+9])
                tptr+=bread
                CRCs = []
                if hbyte == 0x0: #(kEnd)
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    break
                elif hbyte == 0xa: #kCRC 
                    boolVec = []
                    print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                    # start ReadHashDigests(numFolders, folderCRCs)
                    allAreDefined,bread = read_number(tail[tptr:tptr+9])
                    print "allAreDefined  : 0x%02x" % (allAreDefined)
                    tptr+=bread
                    if allAreDefined == 0:
                        #ReadBoolVector(1,v)
                        # just being lazy and only reading 1 item XD
                        for i in range(0,numFolders%8):
                            boolVec.append(ord(tail[tptr]))
                            tptr+=1
                    else: 
                        #sets entire CBoolVector as true...
                        for i in range(0,numFolders%8):
                            boolVec.append(0xff)
                        
                    print "CRCBoolVec     : %s" % str(boolVec)
                
                    for i in range(0,numFolders):
                        crc = struct.unpack(">I",tail[tptr:tptr+4])[0]
                        tptr+=4
                        CRCs.append(crc)
                        print "CRC[%i]         : 0x%08x"%(i,crc) 
                        
                    
            
                else:
                    skip,bread = read_number(tail[tptr:tptr+9])
                    tptr+=(bread+skip) 
                    print "Skipping %d bytes" % skip

    
            # at this point we shift over to the data header
            print "============Begin packed header parsing (0x%lx,0x%x)=================" %(dataOffset,packSize)
            from Crypto.Cipher import AES 
            import hashlib
            s =hashlib.sha256()

            eptr = dataOffset 
            cryptBuffer = _7zbuff[eptr:packSize]
            tmpkey = "QggGPGqdMtzMmO2RROSCpaSRo1iKEAp8"                 
            realkey = ""
            for c in tmpkey:
                realkey+="\x00"
                realkey+=c
                
            for i in range(0,1<<NumCyclesPower):
                s.update(realkey) 

            realkey = s.digest()
            print "AES Key hashed alot: %s" % "\\x"+"\\x".join("%02x"%ord(c) for c in realkey)

            d = AES.new(realkey,AES.MODE_CBC,IV) #third param == IV. Do we need one?
            decryptedBuffer = d.decrypt(cryptBuffer)
        
            buf = ""
            if not len(decryptedBuffer):
                print "[;_;] Could not get the decrypted buffer..." 
                sys.exit()
            
            for i in range(0,len(decryptedBuffer)):
                buf += "\\x%02x"%ord(decryptedBuffer[i]) 
            print buf

            # Now we start reading all the headers and stuff....  
            





    # lol, okay, so what if it's unencoded...?
    elif hbyte == 0x1: #kHeader 
        hbyte,bread = read_number(tail[tptr:tptr+9])  
        print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
        tptr+=bread 

        if hbyte != 0x4:   #0x4:"kMainStreamsInfo",
            print "[x.x] invalid next header, expecting 0x4."
            sys.exit()
    
        if hbyte == 0x4:  # kMainStreamsInfo
            # ReadStreamsInfo() 
            hbyte,bread = read_number(tail[tptr:tptr+9])  
            print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
            tptr+=bread 

            if hbyte == 0x6: # kPackInfo 
                dataOffset,bread = read_number(tail[tptr:tptr+9])  
                print "dataOffset     : 0x%02x" % (dataOffset)
                tptr+=bread 
            
            hbyte,bread = read_number(tail[tptr:tptr+9])  
            print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
            tptr+=bread 

            if hbyte == 0x2:    # kArchiveProperties
                #ReadArchiveProperties()
                hbyte,bread = read_number(tail[tptr:tptr+9])  
                print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                tptr+=bread 


            if hbyte == 0x3:  # kAdditionalStreamsInfo
                #ReadAndDecodePackedstreams (same as other?idk.)
                hbyte,bread = read_number(tail[tptr:tptr+9])  
                print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                tptr+=bread 
        
        
         
            if hbyte == 0x5:  # kFilesInfo
                # do a bunch of shit.
                hbyte,bread = read_number(tail[tptr:tptr+9])  
                print "Hbyte          : 0x%02x (%s)" % (hbyte,hdict[hbyte])
                tptr+=bread 

##########################################
####### Begin utility functions ##########
##########################################
# This encoding.... XD 
# can return 1-8 byte number based on a "mask" 
# Reads the first byte, and, moving left to right
# checks bits, and keeps reading new bits until it 
# finds an unset bit. 
# It then looks at anything after the '0', and or's
# that against the final total. 
# But if byte &0x80 => 0, just return 1 byte.
##########################################

def read_number(inp): 
    inp_len = len(inp)-1
    mask = ord(inp[0]) 
    value = 0 
    
    if (mask & 0x80) == 0 or (mask == 0x0):
        return (mask,1)
    
    ormask = (mask - 0x80) 
    #print "ormask: %s" % hex(ormask)
    unpack_str = "B" #lololol
    
    for i in range(1,inp_len):
        if mask & (0x80 >> i): # bit set, read a byte 
            #print hex(ord(inp[i]))
            unpack_str += "B"          
            ormask -= 1<<(8-(i+1))
        else: #  
            try:
                valuetup = struct.unpack(unpack_str,inp[1:(i+1)])
                ormask <<= (i*8)
                break
            except Exception as e: 
                print "Invalid value %s, %d"%(repr(inp),len(inp))
                print unpack_str
                raise
                # not enough bytes given. Error


    for j in range(len(valuetup),0,-1):
        value+=valuetup[j-1]<<(8*(j-1)) 

    if value < 0: 
        value *= -1
    #print "value: 0x%lx, ormask: %s"%(value,hex(ormask))
    value |= ormask
    return (value,i+1)

    

# constsants stolen from 7z source code <3
hdict = {
 0x0:"kEnd",
 0x1:"kHeader",
 0x2:"kArchiveProperties",
 0x3:"kAdditionalStreamsInfo",
 0x4:"kMainStreamsInfo",
 0x5:"kFilesInfo",
 0x6:"kPackInfo",
 0x7:"kUnpackInfo",
 0x8:"kSubStreamsInfo",
 0x9:"kSize",
 0xa:"kCRC",
 0xb:"kFolder",
 0xc:"kCodersUnpackSize",
 0xd:"kNumUnpackStream",
 0xe:"kEmptyStream",
 0xf:"kEmptyFile",
 0x10:"kAnti",
 0x11:"kName",
 0x12:"kCTime",
 0x13:"kATime",
 0x14:"kMTime",
 0x15:"kWinAttrib",
 0x16:"kComment",
 0x17:"kEncodedHeader",
 0x18:"kStartPos",
 0x19:"kDummy",
}
#kNtSecure,
#kParent,
#kIsAux

cDict = {
0:"k_Copy", 
3:"k_Delta", 
0x21:"k_LZMA2 = ",
0x20302:"k_SWAP2", 
0x20304:"k_SWAP4", 
0x30101:"k_LZMA" , 
0x30401:"k_PPMD" , 
0x40108:"k_Deflate", 
0x40202:"k_BZip2"  , 
0x3030103:"k_BCJ"  , 
0x303011B:"k_BCJ2" , 
0x3030205:"k_PPC"  , 
0x3030401:"k_IA64" , 
0x3030501:"k_ARM"  , 
0x3030701:"k_ARMT" , 
0x3030805:"k_SPARC", 
0x6F10701:"k_AES"  , 
}



if __name__ == "__main__":
    main()
