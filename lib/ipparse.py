#!/usr/bin/env python
#coding=utf8

#parse ip
class Ipparse():
    # convert an IP address from its dotted-quad format to its 
    # 32 binary digit representation
    def __init__(self):
        pass

    # convert a decimal number to binary representation 
    # if d is specified, left-pad the binary number with 0s to that length 
    @staticmethod
    def dec2bin(n,d=None): 
        s = "" 
        while n>0: 
            if n&1: 
                s = "1"+s 
            else: 
                s = "0"+s 
            n >>= 1 
        if d is not None: 
            while len(s)<d: 
                s = "0"+s 
        if s == "": s = "0" 
        return s 

    @staticmethod
    def ip2bin(ip): 
        b = "" 
        inQuads = ip.split(".") 
        outQuads = 4 
        for q in inQuads: 
            if q != "": 
                b += Ipparse.dec2bin(int(q),8) 
                outQuads -= 1 
        while outQuads > 0: 
            b += "00000000" 
            outQuads -= 1 
        return b 
    
    # convert a binary string into an IP address
    @staticmethod 
    def bin2ip(b): 
        ip = "" 
        for i in range(0,len(b),8): 
            ip += str(int(b[i:i+8],2))+"." 
        return ip[:-1] 

    # print a list of IP addresses based on the CIDR block specified
    @staticmethod 
    def listCIDR(c):
        cidrlist = []
        if c.find('-') == -1:
            parts = c.split("/")
            baseIP = Ipparse.ip2bin(parts[0])
            subnet = int(parts[1])
            if subnet == 32:
                cidrlist.append(Ipparse.bin2ip(baseIP))
                return cidrlist
            elif subnet > 32:
                return []
            else:
                ipPrefix = baseIP[:-(32-subnet)]
                for i in range(2**(32-subnet)):
                    cidrlist.append(Ipparse.bin2ip(ipPrefix+Ipparse.dec2bin(i, (32-subnet)))) 
                return cidrlist 
        else:
            parts = c.split('-')
            baseIP = parts[0].split('.')
            iptmp = baseIP[0] + '.' + baseIP[1] + '.' + baseIP[2] + '.'
            startIP = baseIP[3]
            endIP = parts[1]
            for a in range(int(startIP), int(endIP)+1):
                ipNew = iptmp + str(a)
                cidrlist.append(ipNew)
            return cidrlist