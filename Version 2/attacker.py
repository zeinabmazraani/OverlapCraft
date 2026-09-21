# Attacker (Version 2) Code:

#Import Libraries:
import sys

#Import Functions:
from helper_functs.attackParamClass import attackParamClass
from helper_functs.rawsocket import rawSockGen
from helper_functs.ipFormCheck import ipFormCheck
from helper_functs.ipHeadFieldGen import ipHeadFieldGen
from helper_functs.simpleOverlapAttack import simpleOverlapAttackParam,simpleOverlapAttack


print("Attacker Version 1.0\n")

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
        
attackParams=simpleOverlapAttackParam(srcIP,dstIP)
simpleOverlapAttack(attackParams)