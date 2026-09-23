#IP Header Field Generator Function:

import socket
import struct

def overflowChecker(ipHead):
    if ((ipHead >> 16)==0):#check for any overflow and set the boolean accordingly 
        isOverflow=False
    else:
        isOverflow=True

    return isOverflow

def checksumGen(ipHeadPack): # Reference: [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-004), [oneuptime_3] 
    checksum=0 # initally set to 0 (this is step 1 in AI output reference)

    ipHeadSize=len(ipHeadPack)

    for i in range(0,ipHeadSize,2): #split the header into 16-bit words and sum them together (these are steps 2 and 3 in AI output reference above)
        checksum+=(ipHeadPack[i] << 8)+ipHeadPack[i+1]

    isOverflow=overflowChecker(checksum) #initially set overflow boolean

    while (isOverflow==True): 
        checksum=(checksum >> 16)+(checksum&0xFFFF) #for overflows, we do end-around carry (i.e. fold the 16th bit back into the 16-bit sum until we have no overflow)
        isOverflow=overflowChecker(checksum) #update overflow boolean to know when to stop (when we don't have overflow anymore)

    finalChecksum=(~checksum)&0xFFFF #take 1's complement of the final checksum value (this is step 4 in AI output reference)

    return finalChecksum

def ipHeadFieldGen(srcIPAddr,destIPAddr,IDField,TTL,protoField,fragSize,fragOffset,isLastFrag):
    ipVers=4 #default: Reference [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-001) 
    IHL=5 #default: Reference [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-001) 
    ipVersIHLcomb=(ipVers << 4) | IHL #combine into an 8-bit value

    servType=0 #default: Reference [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-001) 
    headerLen=IHL*4 #Reference [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-002) 
    totalLen=headerLen+fragSize 

    #Building flag field: Reference [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-003) 
    reservedBitFlag=0
    DFbitFlag=0
    if (isLastFrag==False):
        MFbitFlag=1
    else:
        MFbitFlag=0

    ipFlags=(reservedBitFlag<<2)|(DFbitFlag<<1)|(MFbitFlag) #combine the three flags into a 3-bit value 
    ipFlagsOffsetcomb=(ipFlags<<13)|(fragOffset>>3) #combine flags with offset field for a 16-bit value

    #Transform source and destination Ip addresses to bytes for header 
    #Reference:[rstforums]
    srcIPAddrBytes=socket.inet_aton(srcIPAddr)
    destIPAddrBytes=socket.inet_aton(destIPAddr)

    #Build a dictionary to store all header fields (in order)
    ipHead={
        "ipVers+IHL":ipVersIHLcomb,
        "serviceType":servType,
        "totalLength":totalLen,
        "IDField":IDField,
        "flags+offset":ipFlagsOffsetcomb,
        "TTL":TTL,
        "protocol":protoField,
        "checksum":0, #we can't caluclate checksum at this stage as the packet has not been transformed to raw bytes; as such we set it to zero temporarily to calcualte it afterwards
        "srcIPAddr":srcIPAddrBytes,
        "destIPAddr":destIPAddrBytes,
    }

    #Reference: [AI_Prompts_Outputs](attacker_v1_ipHeadFieldGen-Func_Ref-005-p1,attacker_v1_ipHeadFieldGen-Func_Ref-005-p2) 
    ipHeadPack=struct.pack('!BBHHHBBH4s4s', *ipHead.values()) #packs the IP header into a 20-byte format expected for transmission.

    headChecksum=checksumGen(ipHeadPack) #calculates the checksum of the header (which was previously set to 0 temporarily)
    ipHead["checksum"]=headChecksum #assigns it instead of 0 in the dictionary

    ipHeadPack=struct.pack('!BBHHHBBH4s4s', *ipHead.values()) #repacks the header packet (byte format)

    return ipHeadPack 




    
    

    
    

