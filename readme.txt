usage:  python3  weblogic_bug_scan.py  [ip.txt]  [Thread_num]

1、批量检测weblogic漏洞工具，兼容Linux和Windows

2、自己可以自定义扫描端口，端口字典在   /Payload/default_data/dict_ports.py 

3、所有请求全部通过socket模块进行，为了防止遗漏，web请求相关Payload模块都进行 http/https两种验证模式

4、结果存放在Output目录下

5、工具仅用于安全测试，请勿非法使用
