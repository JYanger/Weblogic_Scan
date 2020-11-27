#!/usr/bin/env Python
# coding=utf-8 
# https://github.com/JYanger   |||  摘自https://www.jb51.net/article/112727.htm

import platform
if 'Windows' in platform.system():
    import sys
    import ctypes
    __stdInputHandle = -10
    __stdOutputHandle = -11
    __stdErrorHandle = -12
    __foreGroundBLUE = 0x09
    __foreGroundGREEN = 0x0a
    __foreGroundRED = 0x0c
    __foreGroundYELLOW = 0x0e
    __foreGroundWRITE= 0x0f
    __foreGroundINTENSITY = 0x08
    stdOutHandle=ctypes.windll.kernel32.GetStdHandle(__stdOutputHandle)
    def setCmdColor(color,handle=stdOutHandle):
        return ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
    def resetCmdColor():
        setCmdColor(__foreGroundRED | __foreGroundGREEN | __foreGroundBLUE)
    def printBlue(msg):
        setCmdColor(__foreGroundBLUE | __foreGroundINTENSITY)
        print(msg)
        resetCmdColor()
    def printGreen(msg):
        setCmdColor(__foreGroundGREEN | __foreGroundINTENSITY)
        print(msg)
        resetCmdColor()
    def printRed(msg):
        setCmdColor(__foreGroundRED | __foreGroundINTENSITY)
        print(msg)
        resetCmdColor()
    def printYellow(msg):
        setCmdColor(__foreGroundYELLOW | __foreGroundINTENSITY)
        print(msg)
        resetCmdColor()
    def printWrite(msg):
        setCmdColor(__foreGroundWRITE | __foreGroundINTENSITY)
        print(msg)
        resetCmdColor()
    def prints(msg):
        print(msg)
else:
    STYLE = {
    'fore':{
    'red': 31,
    'green': 32,
    'yellow': 33,
    'blue': 34,
    'write': 37,
        }
    }
    def UseStyle(msg, mode = '', fore = '', back = '40'):
        fore = '%s' % STYLE['fore'][fore] if STYLE['fore'].__contains__(fore) else ''
        style = ';'.join([s for s in [mode, fore, back] if s])
        style = '\033[%sm' % style if style else ''
        end = '\033[%sm' % 0 if style else ''
        return '%s%s%s' % (style, msg, end)
    def printRed(msg):
        print(UseStyle(msg,fore='red'))
    def printGreen(msg):
        print(UseStyle(msg,fore='green'))
    def printYellow(msg):
        print(UseStyle(msg,fore='yellow'))
    def printBlue(msg):
        print(UseStyle(msg,fore='blue'))
    def printWrite(msg):
        print(UseStyle(msg,fore='write'))
    def prints(msg):
        print(msg)
        
