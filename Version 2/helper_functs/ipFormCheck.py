#Check IP Format Function

def ipFormCheck(ipAdrr):
    ipOctets=ipAdrr.split(".")

    ipOctetsLen=len(ipOctets)
    if (ipOctetsLen==4):
        for i in range(ipOctetsLen):
            octet=ipOctets[i]

            isoctetInt=octet.isdigit()
            if (isoctetInt==True):
                octetInt=int(octet)
            else:
                isIpValid=False
                break

            if (octetInt>=0)and(octetInt<=255): 
                if (i==(ipOctetsLen-1)):
                    isIpValid=True
                continue
            else:
                isIpValid=False
                break  
    else:
        isIpValid=False

    return isIpValid