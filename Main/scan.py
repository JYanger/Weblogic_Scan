#!/usr/bin/env Python
# coding=utf-8
#https://github.com/JYanger

import sys,os,queue,threading,time,re
sys.path.append(("".join(list(sys.path[0])[:-4])))
import Thirdpart.banner
import Payload.__poc_num
import Main.Threadpool
from Thirdpart.printmsg import *
from Payload.default_data.dict_ports import ports

run_times = 1

def Import_py_name():
    filelist = []
    pyfiles = []
    for name in os.listdir('.\\Payload'):
            str=os.path.join(('.'), name)
            if str.split('.')[-1]=='py':
                filelist.append(str)
    for i in range(0,len(filelist)):
        #re.findall(r'.\\(.*?).py',filelist[i],re.I)
        pyfiles.append("".join(re.findall(r'.\\(.*?).py',filelist[i],re.I)))#正则匹配转化为str类型，并添加到数组pyfiles
    pyfiles.remove('__init__')
    pyfiles.remove('__poc_num')
    pyfiles.remove('Weblogic_brute')
    '''for j in range(0,len(pyfiles)):
        pyfiles[j] = ('Payload.'+pyfiles[j])
    Import_Files = (",".join(pyfilename))'''
    return pyfiles

def Check_all(ip,port):
     
   f = open('Output/valueable.txt','a')
   for i in range(0,len(Import_py_name())):
       #print('Payload.'+("".join(Import_py_name()[i])))
       try:
           (ip,port) = eval('Payload.'+("".join(Import_py_name()[i]))).check(ip,port)
           if (ip,port):
               if 'Insideip' in Import_py_name()[i]:
                   printBlue('[+] 漏洞名称：{} 漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+'   低危<原理扫描>')
                   f.write('[+] 漏洞名称：{} '.format(Import_py_name()[i])+ip+':'+port+' 低危<原理扫描>\n')
                   (ip,port)=()
               elif 'Weblogic_Console' in Import_py_name()[i]:  
                   if(Payload.Weblogic_brute.brute(ip,port)):      #只有扫出来console接口，才进行弱口令破解
                       (username,password) = Payload.Weblogic_brute.brute(ip,port)
                       printRed('[+] 漏洞名称：{}  漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+'-->用户密码:'+username+'/'+password+'   高危<原理扫描>')
                       f.write('[+] 漏洞名称：{}  漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+'-->用户密码:'+username+'/'+password+'   高危<原理扫描>\n')
                   else:    
                       printYellow('[+] 漏洞名称：{} 漏洞地址//'.format(Import_py_name()[i])+ip+':'+port+'   中危<原理扫描>')
                       f.write('[+] 漏洞名称：{}  漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+' 中危<原理扫描>\n')
                   (ip,port)=()
               elif 'CVE_2019_2618' in Import_py_name()[i]:
                   printYellow('[+] 漏洞名称：{}  漏洞地址//:'.format((Import_py_name()[i]))+ip+':'+port+'   中危[需要验证]')
                   f.write('[+] 漏洞名称：{}  漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+' 中危<原理扫描>\n')
                   (ip,port)=()
               else:
                   printRed('[+] 漏洞名称：{}  漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+'   高危<原理扫描>')
                   f.write('[+] 漏洞名称：{}  漏洞地址//:'.format(Import_py_name()[i])+ip+':'+port+' 高危<原理扫描>\n')
                   (ip,port)=()
       except Exception as e:
           pass
       process()
   f.close()
    
def process():
    global run_times
    iplist = [i.rstrip() for i in open('Survival_URL.txt')]
    sys.stdout.write(">>>>>扫描速度 : %s%%\r"%("%.5f" % (float(float(run_times)/float(int(len(iplist))*len(Import_py_name())))*100)))
    sys.stdout.flush()
    run_times = run_times + 1

def run(ipaddress,Thread_count):
    try:
        th = Main.Threadpool.w8_threadpool(Thread_count, Check_all)
        file = open(ipaddress,'r')
        for ip_port in file.readlines():
            ip_port=ip_port.replace('\n','')
            ip_port=ip_port.replace('\r','')
            th.push(ip_port)
        file.close()
        th.run()
    except Exception as e:
        print(e)
        pass
        
def main():
    Thirdpart.banner.Banner()
    if len(sys.argv)!=3:
        printWrite("e.g: python3 "+os.path.basename(sys.argv[0])+" [iplist.txt] "+"[thread_nums]")
    else:
        import Main.IP_Survival_check
        printWrite("----*--------*--------*--------*--------*--------*--------*--------*--------*--------*-----")
        sys.stdout.write(">>>>>地址[默认端口]存活检测中...请等待\r")
        sys.stdout.flush()
        Main.IP_Survival_check.Survival()
        iplist = [i.rstrip() for i in open('Survival_URL.txt')]
        start_time = time.time()
        printWrite("----*----检测时间: "+ time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
        printWrite("----*----加载Payload数量[/Payload/xxx.py]: %s (默认检测到Console路径才会爆破密码)"%(int(len(Import_py_name())+int(1))))
        printWrite("----*----默认端口字典[/Payload/default_data/dict_ports.py]  : %s"% len(ports))
        printWrite("----*----存活资产数量 : %d "% len(iplist))
        printWrite("----*----检测总次数  : %s"% (int(len(iplist))*len(Import_py_name())))
        run('Survival_URL.txt',int(sys.argv[2]))
        printWrite("----*--------*--------*--------*--------*--------*--------*--------*--------*--------*-----")
        printWrite("----*----结束时间: "+ time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
        Main.IP_Survival_check.text_delte('Survival_URL.txt')

if __name__=="__main__":
    main()
