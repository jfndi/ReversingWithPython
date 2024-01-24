# -*- coding: utf-8 -*-
"""

Creation on Tue Jan 23 13:27:21 2024

Author: kyria (Jean-François Ndi)
 
"""

import ctypes as ct
import ctypes.wintypes as wt

#
# Missing wintypes.
#
ULONGLONG = ct.c_ulonglong

#
# Signatures.
#
IMAGE_DOS_SIGNATURE     = 0x5A4D
IMAGE_NT_SIGNATURE      = 0x00004550

#
# Image file type.
#
IMAGE_FILE_RELOCS_STRIPPED         = 0x0001 
IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002 
IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004 
IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008 
IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010 
IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020 
IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080 
IMAGE_FILE_32BIT_MACHINE           = 0x0100 
IMAGE_FILE_DEBUG_STRIPPED          = 0x0200 
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400 
IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800 
IMAGE_FILE_SYSTEM                  = 0x1000 
IMAGE_FILE_DLL                     = 0x2000 
IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000 
IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000 
IMAGE_FILE_MACHINE_UNKNOWN         = 0
IMAGE_FILE_MACHINE_TARGET_HOST     = 0x0001 
IMAGE_FILE_MACHINE_I386            = 0x014c 
IMAGE_FILE_MACHINE_R3000           = 0x0162 
IMAGE_FILE_MACHINE_R4000           = 0x0166 
IMAGE_FILE_MACHINE_R10000          = 0x0168 
IMAGE_FILE_MACHINE_WCEMIPSV2       = 0x0169 
IMAGE_FILE_MACHINE_ALPHA           = 0x0184 
IMAGE_FILE_MACHINE_SH3             = 0x01a2 
IMAGE_FILE_MACHINE_SH3DSP          = 0x01a3
IMAGE_FILE_MACHINE_SH3E            = 0x01a4 
IMAGE_FILE_MACHINE_SH4             = 0x01a6 
IMAGE_FILE_MACHINE_SH5             = 0x01a8 
IMAGE_FILE_MACHINE_ARM             = 0x01c0 
IMAGE_FILE_MACHINE_THUMB           = 0x01c2 
IMAGE_FILE_MACHINE_ARMNT           = 0x01c4 
IMAGE_FILE_MACHINE_AM33            = 0x01d3
IMAGE_FILE_MACHINE_POWERPC         = 0x01F0 
IMAGE_FILE_MACHINE_POWERPCFP       = 0x01f1
IMAGE_FILE_MACHINE_IA64            = 0x0200 
IMAGE_FILE_MACHINE_MIPS16          = 0x0266 
IMAGE_FILE_MACHINE_ALPHA64         = 0x0284 
IMAGE_FILE_MACHINE_MIPSFPU         = 0x0366 
IMAGE_FILE_MACHINE_MIPSFPU16       = 0x0466 
IMAGE_FILE_MACHINE_AXP64           = IMAGE_FILE_MACHINE_ALPHA64
IMAGE_FILE_MACHINE_TRICORE         = 0x0520 
IMAGE_FILE_MACHINE_CEF             = 0x0CEF
IMAGE_FILE_MACHINE_EBC             = 0x0EBC 
IMAGE_FILE_MACHINE_AMD64           = 0x8664 
IMAGE_FILE_MACHINE_M32R            = 0x9041 
IMAGE_FILE_MACHINE_ARM64           = 0xAA64 
IMAGE_FILE_MACHINE_CEE             = 0xC0EE

#
# Header optional header magic.
#
IMAGE_NT_OPTIONAL_HDR32_MAGIC   = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC   = 0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC    = 0x107

#
# Subsystem values.
#
IMAGE_SUBSYSTEM_UNKNOWN                     = 0   
IMAGE_SUBSYSTEM_NATIVE                      = 1   
IMAGE_SUBSYSTEM_WINDOWS_GUI                 = 2   
IMAGE_SUBSYSTEM_WINDOWS_CUI                 = 3   
IMAGE_SUBSYSTEM_OS2_CUI                     = 5   
IMAGE_SUBSYSTEM_POSIX_CUI                   = 7   
IMAGE_SUBSYSTEM_NATIVE_WINDOWS              = 8   
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI              = 9   
IMAGE_SUBSYSTEM_EFI_APPLICATION             = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          = 12
IMAGE_SUBSYSTEM_EFI_ROM                     = 13
IMAGE_SUBSYSTEM_XBOX                        = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    = 16
IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG           = 17

#
# Dll characteristics.
#
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA        = 0x0020  
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           = 0x0040     
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        = 0x0080     
IMAGE_DLLCHARACTERISTICS_NX_COMPAT              = 0x0100     
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           = 0x0200     
IMAGE_DLLCHARACTERISTICS_NO_SEH                 = 0x0400     
IMAGE_DLLCHARACTERISTICS_NO_BIND                = 0x0800     
IMAGE_DLLCHARACTERISTICS_APPCONTAINER           = 0x1000     
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             = 0x2000     
IMAGE_DLLCHARACTERISTICS_GUARD_CF               = 0x4000     
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  = 0x8000

#
# Directory entries.
#
IMAGE_DIRECTORY_ENTRY_EXPORT            = 0   
IMAGE_DIRECTORY_ENTRY_IMPORT            = 1   
IMAGE_DIRECTORY_ENTRY_RESOURCE          = 2   
IMAGE_DIRECTORY_ENTRY_EXCEPTION         = 3   
IMAGE_DIRECTORY_ENTRY_SECURITY          = 4   
IMAGE_DIRECTORY_ENTRY_BASERELOC         = 5   
IMAGE_DIRECTORY_ENTRY_DEBUG             = 6   
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      = 7   
IMAGE_DIRECTORY_ENTRY_GLOBALPTR         = 8   
IMAGE_DIRECTORY_ENTRY_TLS               = 9   
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       = 10   
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      = 11   
IMAGE_DIRECTORY_ENTRY_IAT               = 12   
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      = 13   
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    = 14   

class IMAGE_DOS_HEADER(ct.Structure):
    _fields_ = [
        ("e_magic",         wt.WORD),
        ("e_cblp",          wt.WORD),
        ("e_cp",            wt.WORD),
        ("e_crlc",          wt.WORD),
        ("e_cparhdr",       wt.WORD),
        ("e_minalloc",      wt.WORD),
        ("e_maxalloc",      wt.WORD),
        ("e_ss",            wt.WORD),
        ("e_sp",            wt.WORD),
        ("e_csum",          wt.WORD),
        ("e_ip",            wt.WORD),
        ("e_cs",            wt.WORD),
        ("e_lfarlc",        wt.WORD),
        ("e_ovno",          wt.WORD),
        ("e_res",           wt.DWORD * 4),
        ("e_oemid",         wt.WORD),
        ("e_oeminfo",       wt.WORD),
        ("e_res2",          wt.WORD * 10),
        ("e_lfanew",        wt.LONG),
        ]

class IMAGE_FILE_HEADER(ct.Structure):
    _fields_ = [
        ("Machine",                 wt.WORD),
        ("NumberOfSections",        wt.WORD),
        ("TimeDateStamp",           wt.DWORD),
        ("PointerToSymbolTable",    wt.DWORD),
        ("NumberOfSymbols",         wt.DWORD),
        ("SizeOfOptionalHeader",    wt.WORD),
        ("Characteristics",         wt.WORD),
        ]
    
IMAGE_SIZEOF_FILE_HEADER    = 20
    
class IMAGE_DATA_DIRECTORY(ct.Structure):
    _fields_ = [
        ("VirtualAddress",      wt.DWORD),
        ("Size",                wt.WORD),
        ]

IMAGE_NUMBEROF_DIRECTORY_ENTRIES    = 16

class IMAGE_OPTIONAL_HEADER32(ct.Structure):
    _fields_ = [
        ("Magic",                       wt.WORD),
        ("MajorLinkerVersion",          wt.BYTE),
        ("MinorLinkerVersion",          wt.BYTE),
        ("SizeOfCode",                  wt.DWORD),
        ("SizeOfInitializedData",       wt.DWORD),
        ("SizeOfUninitializedData",     wt.DWORD),
        ("AddressOfEntryPoint",         wt.DWORD),
        ("BaseOfCode",                  wt.DWORD),
        ("BaseOfData",                  wt.DWORD),
        ("ImageBase",                   wt.DWORD),
        ("SectionAlignment",            wt.DWORD),
        ("FileAlignment",               wt.DWORD),
        ("MajorOperatingSystemVersion", wt.WORD),
        ("MinorOperatingSystemVersion", wt.WORD),
        ("MajorImageVersion",           wt.WORD),
        ("MinorImageVersion",           wt.WORD),
        ("MajorSubsystemVersion",       wt.WORD),
        ("MinorSubsystemVersion",       wt.WORD),
        ("Win32VersionValue",           wt.DWORD),
        ("SizeOfImage",                 wt.DWORD),
        ("SizeOfHeaders",               wt.DWORD),
        ("CheckSum",                    wt.DWORD),
        ("Subsystem",                   wt.WORD),
        ("DllCharacteristics",          wt.WORD),
        ("SizeOfStackReserve",          wt.DWORD),
        ("SizeOfStackCommit",           wt.DWORD),
        ("SizeOfHeapReserve",           wt.DWORD),
        ("SizeOfHeapCommit",            wt.DWORD),
        ("LoaderFlags",                 wt.DWORD),
        ("NumberOfRvaAndSizes",         wt.DWORD),
        ("DataDirectory",               IMAGE_DATA_DIRECTORY * 
         IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
        ]

class IMAGE_OPTIONAL_HEADER64(ct.Structure):
    _fields_ = [
        ("Magic",                       wt.WORD),
        ("MajorLinkerVersion",          wt.BYTE),
        ("MinorLinkerVersion",          wt.BYTE),
        ("SizeOfCode",                  wt.DWORD),
        ("SizeOfInitializedData",       wt.DWORD),
        ("SizeOfUninitializedData",     wt.DWORD),
        ("AddressOfEntryPoint",         wt.DWORD),
        ("BaseOfCode",                  wt.DWORD),
        ("BaseOfData",                  wt.DWORD),
        ("ImageBase",                   ULONGLONG),
        ("SectionAlignment",            wt.DWORD),
        ("FileAlignment",               wt.DWORD),
        ("MajorOperatingSystemVersion", wt.WORD),
        ("MinorOperatingSystemVersion", wt.WORD),
        ("MajorImageVersion",           wt.WORD),
        ("MinorImageVersion",           wt.WORD),
        ("MajorSubsystemVersion",       wt.WORD),
        ("MinorSubsystemVersion",       wt.WORD),
        ("Win32VersionValue",           wt.DWORD),
        ("SizeOfImage",                 wt.DWORD),
        ("SizeOfHeaders",               wt.DWORD),
        ("CheckSum",                    wt.DWORD),
        ("Subsystem",                   wt.WORD),
        ("DllCharacteristics",          wt.WORD),
        ("SizeOfStackReserve",          ULONGLONG),
        ("SizeOfStackCommit",           ULONGLONG),
        ("SizeOfHeapReserve",           ULONGLONG),
        ("SizeOfHeapCommit",            ULONGLONG),
        ("LoaderFlags",                 wt.DWORD),
        ("NumberOfRvaAndSizes",         wt.DWORD),
        ("DataDirectory",               IMAGE_DATA_DIRECTORY * 
         IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
        ]
    
class IMAGE_ROM_OPTIONAL_HEADER(ct.Structure):
    _fields_ = [
        ("Magic",                       wt.WORD),
        ("MajorLinkerVersion",          wt.BYTE),
        ("MinorLinkerVersion",          wt.BYTE),
        ("SizeOfCode",                  wt.DWORD),
        ("SizeOfInitializedData",       wt.DWORD),
        ("SizeOfUninitializedData",     wt.DWORD),
        ("AddressOfEntryPoint",         wt.DWORD),
        ("BaseOfCode",                  wt.DWORD),
        ("BaseOfBss",                   wt.DWORD),
        ("GprMask",                     wt.DWORD),
        ("CprMask",                     wt.DWORD * 4),
        ("GpValue",                     wt.DWORD),
        ]
    
class IMAGE_NT_HEADERS64(ct.Structure):
    _fields_ = [
        ("Signature",       ct.DWORD),
        ("FileHeader",      IMAGE_FILE_HEADER),
        ("OptionalHeader",  IMAGE_OPTIONAL_HEADER64),
        ]
    
class IMAGE_NT_HEADERS32(ct.Structure):
    _fields_ = [
        ("Signature",       ct.DWORD),
        ("FileHeader",      IMAGE_FILE_HEADER),
        ("OptionalHeader",  IMAGE_OPTIONAL_HEADER32),
        ]
    
class IMAGE_ROM_HEADERS32(ct.Structure):
    _fields_ = [
        ("FileHeader",      IMAGE_FILE_HEADER),
        ("OptionalHeader",  IMAGE_ROM_OPTIONAL_HEADER),
        ]
