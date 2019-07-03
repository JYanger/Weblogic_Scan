#!/usr/bin/env python
#encoding: utf-8
import ctypes
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE= -11
STD_ERROR_HANDLE = -12
FOREGROUND_BLACK = 0x0
FOREGROUND_BLUE = 0x01 # text color contains blue.   01蓝色
FOREGROUND_WRITE = 0x07 # text color contains blue.  07亮白色
FOREGROUND_GREEN= 0x02 # text color contains green. 02 绿色
FOREGROUND_RED = 0x04 # text color contains red.     04红色
FOREGROUND_YELLOW= 0x06 # text color contains yellow. 06黄色
FOREGROUND_INTENSITY = 0x08 # text color is intensified. 字体颜色加强
class Color:
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    def set_cmd_color(self, color, handle=std_out_handle):
        bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
        return bool
    def reset_color(self):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_WRITE)
    def print_red_text(self, print_text):
        self.set_cmd_color(FOREGROUND_RED | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_green_text(self, print_text):
        self.set_cmd_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_write_text(self, print_text):
        self.set_cmd_color(FOREGROUND_WRITE | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_blue_text(self, print_text):
        self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
    def print_yellow_text(self, print_text):
        self.set_cmd_color(FOREGROUND_YELLOW | FOREGROUND_INTENSITY)
        print print_text
        self.reset_color()
        
if __name__ == "__main__":
    clr = Color()
    clr.print_red_text('red')
    clr.print_green_text('green')
    clr.print_blue_text('blue')
