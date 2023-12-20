# -*- coding: utf-8 -*-
"""

Creation on Wed Dec 20 03:31:59 2023

Author: kyria (Jean-François Ndi)

Use of ctypes to call a function is the Windows C-Runtime library.
 
"""
from ctypes import cdll

msvcrt = cdll.msvcrt
message_string = "Hello, World!\n"
msvcrt.wprintf("Testing: %s", message_string)
