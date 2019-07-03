#!/usr/bin/env Python
# coding=utf-8
#https://github.com/JYanger

import platform


def UsePlatform():#判断当前操作系统为Windows还是Linux
    sysstr = platform.system()
    return sysstr

 
if __name__=="__main__":
    if (UsePlatform()) == "Windows":
        import Weblogic_Bug_Scan_Windows
        Weblogic_Bug_Scan_Windows.main()
    else:
        import Weblogic_Bug_Scan_Linux
        Weblogic_Bug_Scan_Linux.main()

