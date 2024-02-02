# -*- coding: utf-8 -*-
"""

Creation on Fri Feb  2 09:11:33 2024

Author: kyria (Jean-François Ndi)
 
"""

import ctypes as ct
import elf_defines as ed

#
# ELF file header.
#
class Elf32_Ehdr(ct.Structure):
    _fields_ = [
        ("e_ident",         ct.c_ubyte * ed.EI_NIDENT),
        ("e_type",          ed.Elf32_Half),
        ("e_machine",       ed.Elf32_Half),
        ("e_entry",         ed.Elf32_Addr),
        ("e_phoff",         ed.Elf32_Off),
        ("e_shoff",         ed.Elf32_Off),
        ("e_flags",         ed.Elf32_Word),
        ("e_ehsize",        ed.Elf32_Half),
        ("e_phentsize",     ed.Elf32_Half),
        ("e_phnum",         ed.Elf32_Half),
        ("e_shentsize",     ed.Elf32_Half),
        ("e_shnum",         ed.Elf32_Half),
        ("e_shstrndx",      ed.Elf32_Half),
        ]

class Elf64_Ehdr(ct.Structure):
    _fields_ = [
        ("e_ident",         ct.c_ubyte * ed.EI_NIDENT),
        ("e_type",          ed.Elf64_Half),
        ("e_machine",       ed.Elf64_Half),
        ("e_entry",         ed.Elf64_Addr),
        ("e_phoff",         ed.Elf64_Off),
        ("e_shoff",         ed.Elf64_Off),
        ("e_flags",         ed.Elf64_Word),
        ("e_ehsize",        ed.Elf64_Half),
        ("e_phentsize",     ed.Elf64_Half),
        ("e_phnum",         ed.Elf64_Half),
        ("e_shentsize",     ed.Elf64_Half),
        ("e_shnum",         ed.Elf64_Half),
        ("e_shstrndx",      ed.Elf64_Half),
        ]

#
# Section header.
#
class Elf32_Shdr(ct.Structure):
    _fields_ = [
        ("sh_name",         ed.Elf32_Word),
        ("sh_type",         ed.Elf32_Word),
        ("sh_flags",        ed.Elf32_Word),
        ("sh_addr",         ed.Elf32_Addr),
        ("sh_offset",       ed.Elf32_Off),
        ("sh_size",         ed.Elf32_Word),
        ("sh_link",         ed.Elf32_Word),
        ("sh_info",         ed.Elf32_Word),
        ("sh_addralign",    ed.Elf32_Word),
        ("sh_entsize",      ed.Elf32_Word),
        ]

class Elf64_Shdr(ct.Structure):
    _fields_ = [
        ("sh_name",         ed.Elf64_Word),
        ("sh_type",         ed.Elf64_Word),
        ("sh_flags",        ed.Elf64_Word),
        ("sh_addr",         ed.Elf64_Addr),
        ("sh_offset",       ed.Elf64_Off),
        ("sh_size",         ed.Elf64_Word),
        ("sh_link",         ed.Elf64_Word),
        ("sh_info",         ed.Elf64_Word),
        ("sh_addralign",    ed.Elf64_Word),
        ("sh_entsize",      ed.Elf64_Word),
        ]
