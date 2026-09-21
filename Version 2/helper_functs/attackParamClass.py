#Attack Class 

class attackParamClass:
    def __init__(self,srcIPAddr,destIPAddr,IDField,TTL,protoField,fragSize,allFragms):
        self.srcIPAddr=srcIPAddr
        self.destIPAddr=destIPAddr
        self.IDField=IDField
        self.TTL=TTL
        self.protoField=protoField
        self.fragSize=fragSize
        self.allFragms=allFragms