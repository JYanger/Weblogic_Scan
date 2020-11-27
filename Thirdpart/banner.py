#coding:utf-8
#!/usr/bin/env

from Thirdpart.printmsg import *
import random


TITLE = '''
-----------------------
<Weblogic 漏洞扫描工具>
-----------------------'''

BODY = [
'''    "--"
    (OO)_____
    (__)    ) \\
       ||--||  *
''',

'''        _^_
       /@ @\\
      (  >  )
        [OO]
        /||\\
''',
'''       ____
      //||\\\\
     { p  p }
    __( v )__/
   /  |_ _|
''',
'''  o 0 o
          o 0
              o
|^^^^^^^^^^^^|L___
|  Payload     |''\\___,
|______________|__|)__|
|(@)(@)""**|(@)(@)*|(@)
''',
'''         /\\___/\\
     _____(0 0)
   /(      \\v/
  *  ||----||
'''
]

CVE_NUM = '''
      ________________________________________________
     /  CVE-2014-4210/ Weblog_Console/ Webl_inside_ip/
    / CVE-2016-0638 / CVE-2016-3510 / CVE-2017-3248 /
   / CVE-2017-3506 / CVE-2017-10271/ CVE-2018-2628 /
  / CVE-2018-2893 / CVE-2018-2894 / CVE-2019-2725 / 
 / CVE-2019-2729 / CVE-2019-2618 / CVE-2019-2890 /
/ CVE-2020-2551 / CVE-2020-14750/ CVE-20XX-XXXX /
------------------------------------------------'''


def Banner():
    printBlue(TITLE)
    printGreen(BODY[random.randint(0,4)])
    #printWrite(CVE_NUM)

if __name__=='__main__':
    B = Banner()
