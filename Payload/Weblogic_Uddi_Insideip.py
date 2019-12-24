#coding:utf-8
#!/usr/bin/env Python
#(Weblogic_Uddi_Insideip)

import socket
import ssl
import default_data.dict_ports

socket.setdefaulttimeout(1)

def check(ip):
    for port in default_data.dict_ports.ports:
        try:
            client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            client1.connect((ip,int(port)))
            client1.sendall('''GET /uddi/uddilistener HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(ip,port))
            #print client1.recv(1024)
            buf1 = ""                                                   # 重要 ！！！ 接收分块传输数据包
            buf = "1"
            while len(buf):
                try:
                    #print buf
                    buf1 = buf1 + buf
                    buf = client1.recv(1024)
                except socket.error as e:
                    break
            #print buf1                                                 #将接收到的分块传输包，汇总到buf1，输出（此处调试使用）
            client1.close()
            if "Your message reached this servlet via" in buf1 or "Deploying Application" in buf1:
                #print ip,port
                return ip,port   
        except socket.error as e:
            pass
        
        try:
            client2 = ssl.wrap_socket(socket.socket())
            client2.connect((ip,int(port)))
            client2.sendall('''GET /uddi/uddilistener HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(ip,port))
            buf1 = ""                                                  
            buf = "1"
            while len(buf):
                try:
                    buf1 = buf1 + buf
                    buf = client1.recv(1024)
                except socket.error as e:
                    break
            client2.close()
            if "Your message reached this servlet via" in buf1 or "Deploying Application" in buf1:
                return ip,port    
        except socket.error as e:
            pass
       
if __name__=='__main__':
    check('192.168.2.110')

