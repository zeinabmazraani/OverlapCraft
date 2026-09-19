#Raw Socket Generator Function:

import socket

def rawSockGen():
    #Reference: [rstforums]
    rawSock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) #create a raw socket to only send the raw crafted packet (header+payload)
    rawSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #tell the kernel to not regenerate the header (take it as is)
    return rawSock