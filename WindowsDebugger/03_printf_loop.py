# -*- coding: utf-8 -*-
"""

Creation on Mon Jan  8 15:02:46 2024

Author: kyria (Jean-François Ndi)
 
"""

from ctypes import *
import time

msvcrt = cdll.msvcrt
counter = 0

while 1:
    msvcrt.wprintf(f"Loop iteration {counter}!\n")
    time.sleep(2)
    counter += 1
