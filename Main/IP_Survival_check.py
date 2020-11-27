#!/usr/bin/env Python
# coding=utf-8
#https://github.com/JYanger

import sys,os,socket,ssl,queue,threading,time
sys.path.append(("".join(list(sys.path[0])[:-4])))
import Payload.default_data.dict_ports
import Main.Threadpool
from Thirdpart.printmsg import *
socket.setdefaulttimeout(1)

IPcount = 0

def text_create(msg):
    file = open('Survival_URL.txt', 'a+')
    file.write(msg) 
    file.close()
        
def text_delte(msg):
    os.remove(msg)

def Remove_duplication(msg):
    result=[]
    with open(msg,'r') as f:
        for line in f:
            result.append(line.strip('\n').strip('\r'))
    os.remove(msg)
    for i in list(set(result)):
        text_create(i+'\n')

def check(ip):
    global IPcount
    for port in Payload.default_data.dict_ports.ports:
        try:
            client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            client1.connect((ip,int(port)))
            client1.send(str.encode('''GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(ip,port)))
            buf = client1.recv(1024)
            client1.close()
            if buf !='':
                text_create(str(ip)+'\n')
                IPcount = 1
                return  
        except socket.error as e:
            pass
        
        try:
            client2 = ssl.wrap_socket(socket.socket())
            client2.connect((ip,int(port)))
            client2.sendall(str.encode('''GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n'''.format(ip,port)))
            buf1 = client1.recv(1024)
            client2.close()
            if buf1 !='':
                text_create(str(ip)+'\n')
                IPcount = 1
                return  
        except socket.error as e:
            pass
        
def main(iplist,Thread_nums):
    try:
        th = Main.Threadpool.w8_threadpool(Thread_nums, check)
        file = open(iplist,'r')
        for ip in file.readlines():
            ip=ip.replace('\n','')
            ip=ip.replace('\r','')
            th.push(ip)
        file.close()
        th.run()
    except Exception as e:
        print(e)
        pass

def Survival():
    main(sys.argv[1],int(sys.argv[2]))
    time.sleep(2)
    if IPcount == 0:
        printRed('[!] 检测没有发现存活主机，程序自动退出...')
        sys.exit(0)
    else:
        Remove_duplication('Survival_URL.txt')
        
if __name__=="__main__":
    Remove_duplication('Survival_URL.txt')

