# -*- coding: utf-8 -*-
"""

Creation on Wed Dec 20 10:30:13 2023

Author: kyria (Jean-François Ndi)
 
"""
import ctypes as ct
import ctypes.wintypes as wt

INFINITE = wt.DWORD(-1)
INVALID_VALUE = INFINITE
ULONGLONG = ct.c_ulonglong
DWORD64 = ULONGLONG
LONGLONG = ct.c_longlong
UCHAR = ct.c_ubyte

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
# DEBUG_EVENT flags.
#
DBG_EXCEPTION_HANDLED           = 0x00010001    
DBG_CONTINUE                    = 0x00010002    
DBG_REPLY_LATER                 = 0x40010001    
DBG_TERMINATE_THREAD            = 0x40010003    
DBG_TERMINATE_PROCESS           = 0x40010004    
DBG_CONTROL_C                   = 0x40010005    
DBG_PRINTEXCEPTION_C            = 0x40010006    
DBG_RIPEXCEPTION                = 0x40010007    
DBG_CONTROL_BREAK               = 0x40010008    
DBG_COMMAND_EXCEPTION           = 0x40010009    
DBG_PRINTEXCEPTION_WIDE_C       = 0x4001000A    
DBG_EXCEPTION_NOT_HANDLED       = 0x80010001

#
# CONTEXT flags
#    
CONTEXT_AMD64               = 0x00100000
CONTEXT_CONTROL             = (CONTEXT_AMD64 | 0x00000001)
CONTEXT_INTEGER             = (CONTEXT_AMD64 | 0x00000002)
CONTEXT_SEGMENTS            = (CONTEXT_AMD64 | 0x00000004)
CONTEXT_FLOATING_POINT      = (CONTEXT_AMD64 | 0x00000008)
CONTEXT_DEBUG_REGISTERS     = (CONTEXT_AMD64 | 0x00000010)
CONTEXT_FULL                = (CONTEXT_CONTROL | CONTEXT_INTEGER | \
                                 CONTEXT_FLOATING_POINT)
CONTEXT_ALL                 = (CONTEXT_CONTROL | CONTEXT_INTEGER | \
                                 CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | \
                                 CONTEXT_DEBUG_REGISTERS)
CONTEXT_XSTATE              = (CONTEXT_AMD64 | 0x00000040)
CONTEXT_KERNEL_CET          = (CONTEXT_AMD64 | 0x00000080)
CONTEXT_EXCEPTION_ACTIVE    = 0x08000000
CONTEXT_SERVICE_ACTIVE      = 0x10000000
CONTEXT_EXCEPTION_REQUEST   = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000

#
# Thread desired accesses.
#
THREAD_TERMINATE                    = 0x0001  
THREAD_SUSPEND_RESUME               = 0x0002  
THREAD_GET_CONTEXT                  = 0x0008  
THREAD_SET_CONTEXT                  = 0x0010  
THREAD_QUERY_INFORMATION            = 0x0040  
THREAD_SET_INFORMATION              = 0x0020  
THREAD_SET_THREAD_TOKEN             = 0x0080
THREAD_IMPERSONATE                  = 0x0100
THREAD_DIRECT_IMPERSONATION         = 0x0200
THREAD_SET_LIMITED_INFORMATION      = 0x0400
THREAD_QUERY_LIMITED_INFORMATION    = 0x0800
THREAD_RESUME                       = 0x1000
THREAD_ALL_ACCESS                   = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE
                                       | 0xFFFF)

#
# Thread snapshot flags.
#
TH32CS_SNAPHEAPLIST     = 0x00000001
TH32CS_SNAPPROCESS      = 0x00000002
TH32CS_SNAPTHREAD       = 0x00000004
TH32CS_SNAPMODULE       = 0x00000008
TH32CS_SNAPMODULE32     = 0x00000010
TH32CS_SNAPALL          = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
TH32CS_INHERIT          = 0x80000000

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
    
LPTHREAD_START_ROUTINE = ct.CFUNCTYPE(wt.DWORD, wt.LPVOID)

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
        ("ExceptionRecord",         DWORD64),
        ("ExceptionAddress",        DWORD64),
        ("NumberOfParameters",      wt.DWORD),
        ("ExceptionInformation",    wt.DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

#
# DEBUG Info structures.
#
class EXCEPTION_DEBUG_INFO32(ct.Structure):
    _fields_ = [
        ("ExcepionRecord",      EXCEPTION_RECORD32),
        ("FirstChance",         wt.DWORD),
    ]

class EXCEPTION_DEBUG_INFO64(ct.Structure):
    _fields_ = [
        ("ExcepionRecord",      EXCEPTION_RECORD64),
        ("FirstChance",         wt.DWORD),
    ]

class CREATE_THREAD_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("hThread",             wt.HANDLE),
        ("lpThreadLocalBase",   wt.LPVOID),
        ("lpStartAddress",      LPTHREAD_START_ROUTINE),
    ]

class CREATE_PROCESS_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("hFile",                   wt.HANDLE),
        ("hProcess",                wt.HANDLE),
        ("hThread",                 wt.HANDLE),
        ("lpBaseOfImage",           wt.LPVOID),
        ("dwDebugInfoFileOffset",   wt.DWORD),
        ("nDebugInfoSize",          wt.DWORD),
        ("lpThreadLocalBase",       wt.LPVOID),
        ("lpStartAddress",          LPTHREAD_START_ROUTINE),
        ("lpImageName",             wt.LPVOID),
        ("fUnicode",                wt.WORD),
    ]

class EXIT_THREAD_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("dwExitCode",  wt.DWORD),
    ]

class EXIT_PROCESS_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("dwExitCode",  wt.DWORD),
    ]

class LOAD_DLL_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("hFile",                   wt.HANDLE),
        ("lpBaseOfDll",             wt.LPVOID),
        ("dwDebugInfoFileOffset",   wt.DWORD),
        ("nDebugInfoSize",          wt.DWORD),
        ("lpImageName",             wt.LPVOID),
        ("fUnicode",                wt.WORD),
    ]

class UNLOAD_DLL_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("lpBaseDll",   wt.LPVOID),
    ]

class OUTPUT_DEBUG_STRING_INFO(ct.Structure):
    _fields_ = [
        ("lpDebugStringData",   wt.LPSTR),
        ("fUnicode",            wt.WORD),
        ("nDebugStringLength",  wt.WORD),
    ]

class RIP_INFO(ct.Structure):
    _fields_ = [
        ("dwError", wt.DWORD),
        ("dwType",  wt.DWORD),
    ]

class u32(ct.Union):
    _fields_ = [
        ("Exception",           EXCEPTION_DEBUG_INFO32),
        ("CreateThread",        CREATE_THREAD_DEBUG_INFO),
        ("CreateProcess",       CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread",          EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess",         EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll",             LOAD_DLL_DEBUG_INFO),
        ("UnloadDll",           UNLOAD_DLL_DEBUG_INFO),
        ("DebugString",         OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo",             RIP_INFO),
    ]

class u64(ct.Union):
    _fields_ = [
        ("Exception",           EXCEPTION_DEBUG_INFO64),
        ("CreateThread",        CREATE_THREAD_DEBUG_INFO),
        ("CreateProcess",       CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread",          EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess",         EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll",             LOAD_DLL_DEBUG_INFO),
        ("UnloadDll",           UNLOAD_DLL_DEBUG_INFO),
        ("DebugString",         OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo",             RIP_INFO),
    ]

class DEBUG_EVENT32(ct.Structure):
    _fields_ = [
        ("dwDebugEventCode",    wt.DWORD),
        ("dwProcessId",         wt.DWORD),
        ("dwThreadId",          wt.DWORD),
        ("u",                   u32),
    ]

class DEBUG_EVENT64(ct.Structure):
    _fields_ = [
        ("dwDebugEventCode",    wt.DWORD),
        ("dwProcessId",         wt.DWORD),
        ("dwThreadId",          wt.DWORD),
        ("u",                   u64),
    ]

#
# Thread structures.
#
class THREADENTRY32(ct.Structure):
    _fields_ =[
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ThreadID",        wt.DWORD),
        ("th32OwnerProcessID",  wt.DWORD),
        ("tpBasePri",           wt.LONG),
        ("tpDeltaPri",          wt.LONG),
        ("dwFlags",             wt.DWORD),
    ]
    
class M128A(ct.Structure):
    _pack_ = 16
    _fields_ = [
        ("Low",     ULONGLONG),
        ("High",    LONGLONG),
    ]

class ANONYMSTRUCT(ct.Structure):
    _fields_ = [
        ("Header",      M128A * 2),
        ("Legacy",      M128A * 8),
        ("Xmm0",        M128A),
        ("Xmm1",        M128A),
        ("Xmm2",        M128A),
        ("Xmm3",        M128A),
        ("Xmm4",        M128A),
        ("Xmm5",        M128A),
        ("Xmm6",        M128A),
        ("Xmm7",        M128A),
        ("Xmm8",        M128A),
        ("Xmm9",        M128A),
        ("Xmm10",       M128A),
        ("Xmm11",       M128A),
        ("Xmm12",       M128A),
        ("Xmm13",       M128A),
        ("Xmm14",       M128A),
        ("Xmm15",       M128A),
    ]

class XMM_SAVE_AREA32(ct.Structure):
    _pack_ = 16
    _fields_ = [
        ("ControlWord",         wt.WORD),
        ("StatusWord",          wt.WORD),
        ("TagWord",             wt.BYTE),
        ("Reserved1",           wt.BYTE),
        ("ErrorOpCode",         wt.WORD),
        ("ErrorOffset",         wt.DWORD),
        ("ErrorSelector",       wt.WORD),
        ("Reserved2",           wt.WORD),
        ("DataOffset",          wt.DWORD),
        ("DataSelector",        wt.WORD),
        ("Reserved3",           wt.WORD),
        ("MxCsr",               wt.DWORD),
        ("MxCsr_Mask",          wt.DWORD),
        ("FloatRegister",       M128A * 8),
        ("XmmRegisters",        M128A * 16),
        ("Reserved4",           UCHAR * 96),
    ]  

class ANONYMUNION(ct.Union):
    _fields_ = [
        ("FltSave",         XMM_SAVE_AREA32),
        ("DUMMYSTRUCTNAME", ANONYMSTRUCT),
    ]

class CONTEXT(ct.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home",                  DWORD64),
        ("P2Home",                  DWORD64),
        ("P3Home",                  DWORD64),
        ("P4Home",                  DWORD64),
        ("P5Home",                  DWORD64),
        ("P6Home",                  DWORD64),
        ("ContextFlags",            wt.DWORD),
        ("MxCsr",                   wt.DWORD),
        ("SegCs",                   wt.WORD),
        ("SegDs",                   wt.WORD),
        ("SegEs",                   wt.WORD),
        ("SegFs",                   wt.WORD),
        ("SegGs",                   wt.WORD),
        ("SegSs",                   wt.WORD),
        ("EFlags",                  wt.DWORD),
        ("Dr0",                     DWORD64),
        ("Dr1",                     DWORD64),
        ("Dr2",                     DWORD64),
        ("Dr3",                     DWORD64),
        ("Dr6",                     DWORD64),
        ("Dr7",                     DWORD64),
        ("Rax",                     DWORD64),
        ("Rcx",                     DWORD64),
        ("Rdx",                     DWORD64),
        ("Rbx",                     DWORD64),
        ("Rsp",                     DWORD64),
        ("Rbp",                     DWORD64),
        ("Rsi",                     DWORD64),
        ("Rdi",                     DWORD64),
        ("R8",                      DWORD64),
        ("R9",                      DWORD64),
        ("R10",                     DWORD64),
        ("R11",                     DWORD64),
        ("R12",                     DWORD64),
        ("R13",                     DWORD64),
        ("R14",                     DWORD64),
        ("R15",                     DWORD64),
        ("Rip",                     DWORD64),
        ("DUMMYUNIONNAME",          ANONYMUNION),
        ("VectorRegister",          M128A * 26),
        ("VectorControl",           DWORD64),
        ("DebugControl",            DWORD64),
        ("LastBranchToRip",         DWORD64),
        ("LastBranchFromRip",       DWORD64),
        ("LastExceptionToRip",      DWORD64),
        ("LastExceptionFromRip",    DWORD64),
    ]
