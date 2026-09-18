# Attacker (Version 1) Code:

import sys
from helper_functs.attackParam import attackParamGen, attackParam

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


