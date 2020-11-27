#coding=utf-8
#!/usr/bin/env 
#CVE-2020-2551(IIOP)

import socket
import ssl
import time

def doSendOne(ip,port,data):
    sock=None
    res=None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        server_addr = (ip, int(port))
        sock.connect(server_addr)
        sock.send(data)
        res = sock.recv(20)
        if b'GIOP' in res:
            return True
    except Exception as e:
        pass
    finally:
        if sock!=None:
            sock.close()    
    try:
        sock = ssl.wrap_socket(socket.socket()) 
        sock.settimeout(3)
        server_addr = (ip, int(port))
        sock.connect(server_addr)
        sock.send(data)
        res = sock.recv(20)
        if b'GIOP' in res:
            return True
    except Exception as e:
        pass
    finally:
        if sock!=None:
            sock.close()     
    return False

g_bPipe=False

def check(ip,port):
    global g_bPipe
    if doSendOne(ip,port,bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')):
        return ip,port
    elif g_bPipe == False:
        pass
        
if __name__=='__main__':
    print (check('10.243.74.36'))
