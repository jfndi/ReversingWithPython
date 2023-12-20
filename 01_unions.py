# -*- coding: utf-8 -*-
"""

Creation on Wed Dec 20 06:21:15 2023

Author: kyria (Jean-François Ndi)

This example illustrates the use of ctypes unions.
 
"""
from ctypes import *

class barley_amount(Union):
    _fields_ = [
        ("barley_long",     c_long),
        ("barley_int",      c_int),
        ("barley_char",     c_char * 8),
        ]

value = input("Enter the amount of barley to put into the recipe: ")
my_barley = barley_amount(int(value))
print(f'Barley amount as a long {my_barley.barley_long}')
print(f'Barley amount as an int {my_barley.barley_int}')
print(f'Barley amount as a char {my_barley.barley_char}')
