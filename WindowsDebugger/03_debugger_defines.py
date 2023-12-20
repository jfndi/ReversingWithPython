# -*- coding: utf-8 -*-
"""

Creation on Wed Dec 20 10:30:13 2023

Author: kyria (Jean-François Ndi)
 
"""
import ctypes as ct
import ctypes.wintypes as wt

#
# dwCreationFlags
#
DEBUG_PROCESS                       = 0x00000001
DEBUG_ONLY_THIS_PROCESS             = 0x00000002
CREATE_SUSPENDED                    = 0x00000004
DETACHED_PROCESS                    = 0x00000008

CREATE_NEW_CONSOLE                  = 0x00000010
NORMAL_PRIORITY_CLASS               = 0x00000020
IDLE_PRIORITY_CLASS                 = 0x00000040
HIGH_PRIORITY_CLASS                 = 0x00000080
    
REALTIME_PRIORITY_CLASS             = 0x00000100
CREATE_NEW_PROCESS_GROUP            = 0x00000200
CREATE_UNICODE_ENVIRONMENT          = 0x00000400
CREATE_SEPARATE_WOW_VDM             = 0x00000800

CREATE_SHARED_WOW_VDM               = 0x00001000
CREATE_FORCEDOS                     = 0x00002000
BELOW_NORMAL_PRIORITY_CLASS         = 0x00004000
ABOVE_NORMAL_PRIORITY_CLASS         = 0x00008000
STACK_SIZE_PARAM_IS_A_RESERVATION   = 0x00010000    # Threads only


INHERIT_PARENT_AFFINITY             = 0x00010000
INHERIT_CALLER_PRIORITY             = 0x00020000
CREATE_PROTECTED_PROCESS            = 0x00040000
EXTENDED_STARTUPINFO_PRESENT        = 0x00080000

PROCESS_MODE_BACKGROUND_BEGIN       = 0x00100000
PROCESS_MODE_BACKGROUND_END         = 0x00200000
CREATE_SECURE_PROCESS               = 0x00400000

CREATE_BREAKAWAY_FROM_JOB           = 0x01000000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL    = 0x02000000
CREATE_DEFAULT_ERROR_MODE           = 0x04000000
CREATE_NO_WINDOW                    = 0x08000000

PROFILE_USER                        = 0x10000000
PROFILE_KERNEL                      = 0x20000000
PROFILE_SERVER                      = 0x40000000
CREATE_IGNORE_SYSTEM_DEFAULT        = 0x80000000

#
# STARTUPINFO.dwFlags.
#
STARTF_USESHOWWINDOW        = 0x00000001
STARTF_USESIZE              = 0x00000002
STARTF_USEPOSITION          = 0x00000004
STARTF_USECOUNTCHARS        = 0x00000008
STARTF_USEFILLATTRIBUTE     = 0x00000010
STARTF_RUNFULLSCREEN        = 0x00000020  # Ignored for non-x86 platforms
STARTF_FORCEONFEEDBACK      = 0x00000040
STARTF_FORCEOFFFEEDBACK     = 0x00000080
STARTF_USESTDHANDLES        = 0x00000100

#
# Standard Access types.
#
DELETE                      = 0x00010000
READ_CONTROL                = 0x00020000
WRITE_DAC                   = 0x00040000
WRITE_OWNER                 = 0x00080000
SYNCHRONIZE                 = 0x00100000
STANDARD_RIGHTS_REQUIRED    = 0x000F0000
STANDARD_RIGHTS_READ        = READ_CONTROL
STANDARD_RIGHTS_WRITE       = READ_CONTROL
STANDARD_RIGHTS_EXECUTE     = READ_CONTROL
STANDARD_RIGHTS_ALL         = 0x001F0000
SPECIFIC_RIGHTS_ALL         = 0x0000FFFF

#
# dwDesiredAccess
#
PROCESS_TERMINATE                   = 0x0001  
PROCESS_CREATE_THREAD               = 0x0002  
PROCESS_SET_SESSIONID               = 0x0004  
PROCESS_VM_OPERATION                = 0x0008  
PROCESS_VM_READ                     = 0x0010  
PROCESS_VM_WRITE                    = 0x0020  
PROCESS_DUP_HANDLE                  = 0x0040  
PROCESS_CREATE_PROCESS              = 0x0080  
PROCESS_SET_QUOTA                   = 0x0100  
PROCESS_SET_INFORMATION             = 0x0200  
PROCESS_QUERY_INFORMATION           = 0x0400  
PROCESS_SUSPEND_RESUME              = 0x0800  
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000  
PROCESS_SET_LIMITED_INFORMATION     = 0x2000
PROCESS_ALL_ACCESS                  = (STANDARD_RIGHTS_REQUIRED | 
                                        SYNCHRONIZE | 0xFFFF) 

#
# Structures for CreateProcessA() function.
#
class STARTUPINFOA(ct.Structure):
    _fields_ = [
        ("cb",              wt.DWORD),
        ("lpReserved",      wt.LPSTR),
        ("lpDesktop",       wt.LPSTR),
        ("lpTitle",         wt.LPSTR),
        ("dwX",             wt.DWORD),
        ("dwY",             wt.DWORD),
        ("dwXSize",         wt.DWORD),
        ("dwYSize",         wt.DWORD),
        ("dwXCountChars",   wt.DWORD),
        ("dwYCountChars",   wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags",         wt.DWORD),
        ("wShowWindow",     wt.WORD),
        ("cbReserved2",     wt.WORD),
        ("lpReserved2",     wt.LPBYTE),
        ("hStdInput",       wt.HANDLE),
        ("hStdOutput",      wt.HANDLE),
        ("hStdError",       wt.HANDLE),
    ]

#
# Structures for CreateProcessW() function.
#
class STARTUPINFOW(ct.Structure):
    _fields_ = [
        ("cb",              wt.DWORD),
        ("lpReserved",      wt.LPWSTR),
        ("lpDesktop",       wt.LPWSTR),
        ("lpTitle",         wt.LPWSTR),
        ("dwX",             wt.DWORD),
        ("dwY",             wt.DWORD),
        ("dwXSize",         wt.DWORD),
        ("dwYSize",         wt.DWORD),
        ("dwXCountChars",   wt.DWORD),
        ("dwYCountChars",   wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags",         wt.DWORD),
        ("wShowWindow",     wt.WORD),
        ("cbReserved2",     wt.WORD),
        ("lpReserved2",     wt.LPBYTE),
        ("hStdInput",       wt.HANDLE),
        ("hStdOutput",      wt.HANDLE),
        ("hStdError",       wt.HANDLE),
    ]
    
#
# Common structures.
#
class PROCESS_INFORMATION(ct.Structure):
    _fields_  = [
        ("hProcess",        wt.HANDLE),
        ("hThread",         wt.HANDLE),
        ("dwProcessId",     wt.DWORD),
        ("dwThreadId",      wt.DWORD),
    ]
    
LPTHREAD_START_ROUTINE = ct.CFUNCTYPE(ct.POINTER(ct.DWORD), ct.c_void_p)

#
# EXCEPTION_RECORD structures.
#
EXCEPTION_MAXIMUM_PARAMETERS = 15

class EXCEPTION_RECORD32(ct.Structure):
    _fields_ = [
        ("ExceptionCode",           wt.DWORD),
        ("ExceptionFlags",          wt.DWORD),
        ("ExceptionRecord",         wt.DWORD),
        ("ExceptionAddress",        wt.DWORD),
        ("NumberOfParameters",      wt.DWORD),
        ("ExceptionInformation",    wt.DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

class EXCEPTION_RECORD64(ct.Structure):
    _fields_ = [
        ("ExceptionCode",           wt.DWORD),
        ("ExceptionFlags",          wt.DWORD),
        ("ExceptionRecord",         wt.DWORD64),
        ("ExceptionAddress",        wt.DWORD64),
        ("NumberOfParameters",      wt.DWORD),
        ("ExceptionInformation",    wt.DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

#
# DEBUG Info structures.
#
class EXCEPTION_DEBUG_INFO32(ct.Structure):
    _fields_ = [
        ("ExcepionRecord",      EXCEPTION_RECORD32),
        ("FirstChance",         ct.DWORD),
    ]

class EXCEPTION_DEBUG_INFO64(ct.Structure):
    _fields_ = [
        ("ExcepionRecord",      EXCEPTION_RECORD64),
        ("FirstChance",         ct.DWORD),
    ]

class CREATE_THREAD_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("hThread",             ct.HANDLE),
        ("lpThreadLocalBase",   ct.c_void_p),
        ("lpStartAddress",      LPTHREAD_START_ROUTINE),
    ]
