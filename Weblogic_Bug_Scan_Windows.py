#!/usr/bin/env Python
# coding=utf-8
#https://github.com/JYanger

import sys
import Queue
import threading
import Thirdpart.windows_color
import Thirdpart.banner1
import Payload.Weblogic_Uddi_Insideip
import Payload.Weblogic_Console
import Payload.CVE_2014_4210_SSRF
import Payload.CVE_2016_0638
import Payload.CVE_2016_3510
import Payload.CVE_2017_3248
import Payload.CVE_2017_3506
import Payload.CVE_2017_10271
import Payload.CVE_2018_2628
import Payload.CVE_2018_2893
import Payload.CVE_2018_2894
import Payload.CVE_2019_2725
import Payload.CVE_2019_2729


class MyThread(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self.queue = queue
    def run(self):
        while True:  # 除非确认队列中已经无任务，否则时刻保持线程在运行
            try:
                ip = self.queue.get(block=False)    # 如果队列空了，直接结束线程。根据具体场景不同可能不合理，可以修改
                Check_all(ip,)
            except Exception as e:
                break 


def Check_all(ip):                                  #漏洞检测主模块

    f = file('Output/valueable.txt','a')
    COL = Thirdpart.windows_color.Color()

    
    '''Weblogic_Uddi_Insideip'''
    try:
        if Payload.Weblogic_Uddi_Insideip.check(ip):
            COL.print_blue_text('[+]Weblogic_Uddi_Insideip:        '+str(Payload.Weblogic_Uddi_Insideip.check(ip))+'   Vulnerability level: Low')
            f.write('[+]Weblogic_Uddi_Insideip:        '+str(Payload.Weblogic_Uddi_Insideip.check(ip))+'   Vulnerability level: Low\r\n')
    except Exception as e:
        pass

        
    '''Weblogic_Console'''
    try:
        if Payload.Weblogic_Console.check(ip):
            COL.print_yellow_text('[+]Weblogic_Console:              '+str(Payload.Weblogic_Console.check(ip))+'   Vulnerability level: Middle')
            f.write('[+]Weblogic_Console:              '+str(Payload.Weblogic_Console.check(ip))+'   Vulnerability level: Middle\r\n')
    except Exception as e:
        pass

        
    '''CVE_2014_4210_SSRF'''
    try:
        if Payload.CVE_2014_4210_SSRF.check(ip):
            COL.print_red_text('[+]CVE_2014_4210_SSRF:            '+str(Payload.CVE_2014_4210_SSRF.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2014_4210_SSRF:            '+str(Payload.CVE_2014_4210_SSRF.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass

     
    '''CVE_2016_0638'''
    try:
        if Payload.CVE_2016_0638.check(ip):
            COL.print_red_text('[+]CVE_2016_0638[T3]:             '+str(Payload.CVE_2016_0638.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2016_0638[T3]:             '+str(Payload.CVE_2016_0638.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass

    
    '''CVE_2016_3510'''
    try:
        if Payload.CVE_2016_3510.check(ip):
            COL.print_red_text('[+]CVE_2016_3510[T3]:             '+str(Payload.CVE_2016_3510.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2016_3510[T3]:             '+str(Payload.CVE_2016_3510.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2017_3248'''
    try:
        if Payload.CVE_2017_3248.check(ip):
            COL.print_red_text('[+]CVE_2017_3248[T3]:             '+str(Payload.CVE_2017_3248.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2017_3248[T3]:             '+str(Payload.CVE_2017_3248.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2017_3506'''
    try:
        if Payload.CVE_2017_3506.check(ip):
            COL.print_red_text('[+]CVE_2017_3506[wls-wsat]:       '+str(Payload.CVE_2017_3506.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2017_3506[wls-wsat]:       '+str(Payload.CVE_2017_3506.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2017_10271'''
    try:
        if Payload.CVE_2017_10271.check(ip):
            COL.print_red_text('[+]CVE_2017_10271[wls-wsat]:      '+str(Payload.CVE_2017_10271.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2017_10271[wls-wsat]:      '+str(Payload.CVE_2017_10271.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2018_2628'''
    try:
        if Payload.CVE_2018_2628.check(ip):
            COL.print_red_text('[+]CVE_2018_2628[T3]:             '+str(Payload.CVE_2018_2628.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2018_2628[T3]:             '+str(Payload.CVE_2018_2628.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2018_2893'''
    try:
        if Payload.CVE_2018_2893.check(ip):
            COL.print_red_text('[+]CVE_2018_2893[T3]:             '+str(Payload.CVE_2018_2893.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2018_2893[T3]:             '+str(Payload.CVE_2018_2893.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2018_2894'''
    try:
        if Payload.CVE_2018_2894.check(ip):
            COL.print_red_text('[+]CVE_2018_2894[ws_utc]:         '+str(Payload.CVE_2018_2894.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2018_2894[ws_utc]:         '+str(Payload.CVE_2018_2894.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2019_2725'''
    try:
        if Payload.CVE_2019_2725.check(ip):
            COL.print_red_text('[+]CVE_2019_2725[wls-wsat|_async]:'+str(Payload.CVE_2019_2725.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2019_2725[wls-wsat|_async]:'+str(Payload.CVE_2019_2725.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass


    '''CVE_2019_2729'''
    try:
        if Payload.CVE_2019_2729.check(ip):
            COL.print_red_text('[+]CVE_2019_2729[wls-wsat|_async]:'+str(Payload.CVE_2019_2729.check(ip))+'   Vulnerability level: High')
            f.write('[+]CVE_2019_2729[wls-wsat|_async]:'+str(Payload.CVE_2019_2729.check(ip))+'   Vulnerability level: High\r\n')
    except Exception as e:
        pass

    f.close()
    '''
    try:
        if Payload.CVE_2014_4210_SSRF.check(ip):
            COL.print_red_text('[+]: CVE-2014-4210-SSRF'+str(Payload.CVE_2014_4210_SSRF.check(ip))+'Vulnerability level: High')
    except Exception as e:
        pass
    '''



def run(ipaddress,Thread_count):                     #此处设置线程数
    COL = Thirdpart.windows_color.Color()
    threads = []
    number = 0
    queue = Queue.Queue()
    file = open(ipaddress,'r')
    for ip in file.readlines():
        ip=ip.replace('\n','')
        ip=ip.replace('\r','')
        queue.put(ip)
        number = number+1                            #统计url总数
    file.close()
    for i in range(Thread_count):
        threads.append(MyThread(queue))
    COL.print_write_text("[+]----------------------total ip "+str(number)+"--------------------------")
    for t in threads:
        try:
            t.start()
        except Exception as e:
            print e
            continue
    for t in threads:
        try:
            t.join()
        except Exception as e:
            print e
            continue

def main():
    Thirdpart.banner1.Banner1()
    COL = Thirdpart.windows_color.Color()
    if len(sys.argv)!=3:
        COL.print_write_text('e.g: python2 Weblogic_Bug_Scan.py [ip.txt] [thread_num]')
    else:
        run(sys.argv[1],int(sys.argv[2]))
        COL.print_write_text('check all ip end, bye')
        
'''
if __name__=='__main__':
    Thirdpart.banner.Banner()
    COL = Thirdpart.windows_color.Color()
    if len(sys.argv)!=3:
        COL.print_write_text('e.g: python2 Weblogic_Bug_Scan.py [ip.txt] [thread_num]')
    else:
        run(sys.argv[1],int(sys.argv[2]))
        COL.print_write_text('check all ip end, bey')
'''        
