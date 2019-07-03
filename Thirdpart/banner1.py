#coding:utf-8
#!/usr/bin/env
import windows_color

def Banner1():
    colr = windows_color.Color()
    colr.print_write_text(' ____________________________________________________________')
    colr.print_write_text('|This is a weblogic_bug_scan tool,include the following CVE  |')
    colr.print_write_text('|CVE-2014-4210[SSRF],CVE-2016-0638, CVE-2016-3510            |')
    colr.print_write_text('|CVE-2017-3248, CVE-2018-2628, CVE-2018-2893                 |')
    colr.print_write_text('|CVE-2018-2894, CVE-2017-3506, CVE-2017-10271                |')
    colr.print_write_text('|CVE-2019-2725, CVE-2019-2729                                |')
    colr.print_write_text('|____________________________________________________________|')

def Banner2():
    print('\033[1;37m ____________________________________________________________')
    print('|This is a weblogic_bug_scan tool,include the following CVE  |')
    print('|CVE-2014-4210[SSRF],CVE-2016-0638, CVE-2016-3510            |')
    print('|CVE-2017-3248, CVE-2018-2628, CVE-2018-2893                 |')
    print('|CVE-2018-2894, CVE-2017-3506, CVE-2017-10271                |')
    print('|CVE-2019-2725, CVE-2019-2729                                |')
    print('|____________________________________________________________|\033[0m')



'''
if __name__=='__main__':
    B = banner()
'''
