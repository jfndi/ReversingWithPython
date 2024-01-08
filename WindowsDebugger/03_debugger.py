# -*- coding: utf-8 -*-
"""

Creation on Wed Dec 20 11:49:19 2023

Author: kyria (Jean-François Ndi)
 
"""
import ctypes as ct
import importlib as il

dd = il.import_module('03_debugger_defines')

#
# Kernel32 aliases.
#
kernel32                    = ct.windll.kernel32
CreateProcess               = kernel32.CreateProcessW
GetLastError                = kernel32.GetLastError
OpenProcess                 = kernel32.OpenProcess
DebugActiveProcess          = kernel32.DebugActiveProcess
WaitForDebugEvent           = kernel32.WaitForDebugEvent
ContinueDebugEvent          = kernel32.ContinueDebugEvent
DebugActiveProcessStop      = kernel32.DebugActiveProcessStop
OpenThread                  = kernel32.OpenThread
CreateToolhelp32Snapshot    = kernel32.CreateToolhelp32Snapshot
Thread32First               = kernel32.Thread32First
Thread32Next                = kernel32.Thread32Next
GetThreadContext            = kernel32.GetThreadContext
CloseHandle                 = kernel32.CloseHandle
SuspendThread               = kernel32.SuspendThread
ResumeThread                = kernel32.ResumeThread
ReadProcessMemory           = kernel32.ReadProcessMemory
WriteProcessMemory          = kernel32.WriteProcessMemory
GetModuleHandle             = kernel32.GetModuleNameHandleW
GetProcAddress              = kernel32.GetProcAddress

#
# Debugger structure aliases.
#
STARTUPINFO         = dd.STARTUPINFOW
PROCESS_INFORMATION = dd.PROCESS_INFORMATION
DEBUG_EVENT         = dd.DEBUG_EVENT64
THREADENTRY32       = dd.THREADENTRY32
CONTEXT             = dd.CONTEXT
INVALID_VALUE       = dd.INVALID_VALUE

#
# Debugger define aliases.
#
DBG_CONTINUE                = dd.DBG_CONTINUE
INFINITE                    = dd.INFINITE
DEBUG_PROCESS               = dd.DEBUG_PROCESS
DEBUG_ONLY_THIS_PROCESS     = dd.DEBUG_ONLY_THIS_PROCESS
CREATE_NEW_CONSOLE          = dd.CREATE_NEW_CONSOLE
CREATE_SUSPENDED            = dd.CREATE_SUSPENDED
PROCESS_ALL_ACCESS          = dd.PROCESS_ALL_ACCESS
THREAD_ALL_ACCESS           = dd.THREAD_ALL_ACCESS
TH32CS_SNAPHEAPLIST         = dd.TH32CS_SNAPHEAPLIST 
TH32CS_SNAPPROCESS          = dd.TH32CS_SNAPPROCESS
TH32CS_SNAPTHREAD           = dd.TH32CS_SNAPTHREAD
TH32CS_SNAPMODULE           = dd.TH32CS_SNAPMODULE
TH32CS_SNAPMODULE32         = dd.TH32CS_SNAPMODULE32
TH32CS_SNAPALL              = dd.TH32CS_SNAPALL
TH32CS_INHERIT              = dd.TH32CS_INHERIT
CONTEXT_AMD64               = dd.CONTEXT_AMD64
CONTEXT_CONTROL             = dd.CONTEXT_CONTROL
CONTEXT_INTEGER             = dd.CONTEXT_INTEGER
CONTEXT_SEGMENTS            = dd.CONTEXT_SEGMENTS
CONTEXT_FLOATING_POINT      = dd.CONTEXT_FLOATING_POINT
CONTEXT_DEBUG_REGISTERS     = dd.CONTEXT_DEBUG_REGISTERS
CONTEXT_FULL                = dd.CONTEXT_FULL
CONTEXT_ALL                 = dd.CONTEXT_ALL
CONTEXT_XSTATE              = dd.CONTEXT_XSTATE
CONTEXT_KERNEL_CET          = dd.CONTEXT_KERNEL_CET
CONTEXT_EXCEPTION_ACTIVE    = dd.CONTEXT_EXCEPTION_ACTIVE
CONTEXT_SERVICE_ACTIVE      = dd.CONTEXT_SERVICE_ACTIVE
CONTEXT_EXCEPTION_REQUEST   = dd.CONTEXT_EXCEPTION_REQUEST
CONTEXT_EXCEPTION_REPORTING = dd.CONTEXT_EXCEPTION_REPORTING
DEBUG_EVENT64               = dd.DEBUG_EVENT64
DEBUG_EVENT                 = DEBUG_EVENT64

#
# Debug Event Code
#
EXCEPTION_DEBUG_EVENT       = dd.EXCEPTION_DEBUG_EVENT
CREATE_THREAD_DEBUG_EVENT   = dd.CREATE_THREAD_DEBUG_EVENT
CREATE_PROCESS_DEBUG_EVENT  = dd.CREATE_PROCESS_DEBUG_EVENT
EXIT_THREAD_DEBUG_EVENT     = dd.EXIT_THREAD_DEBUG_EVENT
EXIT_PROCESS_DEBUG_EVENT    = dd.EXIT_PROCESS_DEBUG_EVENT
LOAD_DLL_DEBUG_EVENT        = dd.LOAD_DLL_DEBUG_EVENT
UNLOAD_DLL_DEBUG_EVENT      = dd.UNLOAD_DLL_DEBUG_EVENT
OUTPUT_DEBUG_STRING_EVENT   = dd.OUTPUT_DEBUG_STRING_EVENT
RIP_EVENT                   = dd.RIP_EVENT

debug_event_array   = dd.debug_event_array
debug_event_max     = dd.debug_event_max

class debugger:
    def __init__(self):
        self.__error = 0
        self.__loop = 0
        self.h_process = None
        self.pid = None
        self.h_thread = None
        self.context = None
        self.breakpoints = {}
        self.debugger_active = False
        
        
    def __str__(self):
        if self.h_thread:
            thread_context = dbg.get_thread_context(self.h_thread)
            if thread_context is not None:
                res_str = f'[**] RIP: 0x{thread_context.Rip:016X}\n'
                res_str = res_str + f'[**] RSP: 0x{thread_context.Rsp:016X}\n'
                res_str = res_str + f'[**] RBP: 0x{thread_context.Rbp:016X}\n'
                res_str = res_str + f'[**] RAX: 0x{thread_context.Rax:016X}\n'
                res_str = res_str + f'[**] RBX: 0x{thread_context.Rbx:016X}\n'
                res_str = res_str + f'[**] RCX: 0x{thread_context.Rcx:016X}\n'
                res_str = res_str + f'[**] RDX: 0x{thread_context.Rdx:016X}\n'
                res_str = res_str + f'[**] RSI: 0x{thread_context.Rsi:016X}\n'
                res_str = res_str + f'[**] RDI: 0x{thread_context.Rdi:016X}\n'
                res_str = res_str + f'[**] R8:  0x{thread_context.R8:016X}\n'
                res_str = res_str + f'[**] R9:  0x{thread_context.R9:016X}\n'
                res_str = res_str + f'[**] R10: 0x{thread_context.R10:016X}\n'
                res_str = res_str + f'[**] R11: 0x{thread_context.R11:016X}\n'
                res_str = res_str + f'[**] R12: 0x{thread_context.R12:016X}\n'
                res_str = res_str + f'[**] R13: 0x{thread_context.R13:016X}\n'
                res_str = res_str + f'[**] R14: 0x{thread_context.R14:016X}\n'
                res_str = res_str + f'[**] R15: 0x{thread_context.R15:016X}\n'
                res_str = res_str + f'[**] RIP: 0x{thread_context.Rip:016X}'
            else:
                res_str = '[*] Invalid context returned.'
        else:
            res_str = 'Undefined current thread handle!!!'
        return res_str


    @property
    def error(self):
        return self.__error


    def open_process(self, pid):
        '''
        
        Get a HANDLE to the debuggee.

        Parameters
        ----------
        pid : DWORD
            Debuggee process ID.

        Returns
        -------
        h_process : HANDLE
            Handle to the debuggee process.

        '''
        h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process
    
    
    def debug_loaded_process(self, pid):
        '''
        
        Enter the debug event handling loop.

        Parameters
        ----------
        pid : DWORD
            Target process to be debugged.

        Returns
        -------
        bool
            False: Unable to the debug the target process.
            True: The Event loop was exited gracefully.
        
        Remark: DO NOT call DebugActiveProcess in this context. The process
        has already its debug port set. Calling it will make DebugActiveProcess
        return an error of ERROR_INVALID_PARAMETER. Internally, the actual
        error is STATUS_PORT_ALREADY_SET.

        '''
        self.debugger_active = True
        self.run()


    def load(self, path_to_exe):
        """
        
        Loads and spawns the provided executable.
    
        Parameters
        ----------
        path_to_exe : str
            Path to the executable to be loaded.
    
        Returns
        -------
        None.
    
        """
        #
        # dwCreation flag determines hw to create the process
        # set creation_flags to CREATE_NEW_CONSOLE if we want
        # to see the calculator GUI.
        #
        creation_flags = DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE
        
        #
        # Instantiate the structures.
        #
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        #
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        #
        startupinfo.dwFlags = dd.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0x0
        
        #
        # We then initialize the cb variable in the STARTUP_INFO struct
        # which is just the size of the struct itself.
        #
        startupinfo.cb = ct.sizeof(startupinfo)
        
        if CreateProcess(path_to_exe,
                         None,
                         None,
                         None,
                         False,
                         creation_flags,
                         None,
                         None,
                         ct.byref(startupinfo),
                         ct.byref(process_information)):
            print('[*] We have successfully launched the process!')
            self.pid = process_information.dwProcessId
            print(f'[*] PID {self.pid}')
            
            #
            # Obtain a valid handle to the newly launched process
            # and store it for future access.
            # TODO: Properly handle failure.
            #
            self.h_process = self.open_process(self.pid)
            if not self.h_process:
                #
                # TODO: Properly handle failure.
                #
                self.__error = GetLastError()
                print(f'[*] Unable to get a process handle 0x{self.__error:08X}')
                return
            else:
                print('[*] Process successfully opened.')
                print(f'[*] Returned handle 0x{self.h_process:08X}')
            
            self.debug_loaded_process(self.pid)
        else:
            self.__error = GetLastError()
            #
            # TODO: Properly handle failure.
            #
            print(f'Error: 0x{self.__error:08X}')
            
    
    def debug_attached_process(self, pid):
        '''
        
        Enter the debug event handling loop.

        Parameters
        ----------
        pid : DWORD
            Target process to be debugged.

        Returns
        -------
        bool
            False: Unable to the debug the target process.
            True: The Event loop was exited gracefully.
        
        Remark: DebugActiveProcess should be called in this context as the 
        process is not created but attached to.

        '''
        if DebugActiveProcess(pid):
            self.debugger_active = True
            self.run()
        else:
            #
            # TODO: Properly handle failure.
            #
            print(f'Unable to debug the active process {pid}')
            return False
        return True
        
    
    def attach(self, pid):
        '''
        
        Attach to a running process based on its pid.

        Parameters
        ----------
        pid : DWORD
            Target process to be attached to.

        Returns
        -------
        None.

        '''
        #
        # TODO: Properly handle failure.
        #
        self.pid = pid
        self.h_process = self.open_process(self.pid)
        if not self.h_process:
            #
            # TODO: Properly handle failure.
            #
            self.__error = GetLastError()
            print('[*] Unable to open the attached process ' 
                  f'0x{self.__error:08X}')
        else:
            print('[*] Attached process sucessfully opened')
            print(f'[*] Process handle 0x{self.h_process:08X}')
        
        #
        # We attempt to attach to the process
        # if this fails we exit the call.
        #
        self.debug_attached_process(pid)
            
        
    def run(self):
        '''
        
        Enters the debug event handling loop.

        Returns
        -------
        None.

        '''
        #
        # Now we have to poll the debuggee for
        # debugging events.
        #
        while self.debugger_active == True:
            self.get_debug_event()
        else:
            self.detach()
            
            
    def exception_breakpoint_handler(self):
        print('[***] Inside the breakpoint handler.')
        print('[***] Exception Address: 0x{self.exception_address:016X}.')
        return DBG_CONTINUE
            
            
    def exception_event_handler(self, debug_event):
        exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
        self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress        
        
        if exception == dd.EXCEPTION_ACCESS_VIOLATION:
            print('Access Violation Detected.')
        elif exception == dd.EXCEPTION_BREAKPOINT:
            self.continue_status = self.exception_breakpoint_handler()
        elif exception == dd.EXCEPTION_GUARD_PAGE:
            print('Guard Page Access Detected.')
        elif exception == dd.EXCEPTION_SINGLE_STEP:
            print('Single Stepping.')
        else:
            print('Received: {exception}')
            
    
    def get_debug_event(self):
        if self.__loop >= 10:
            self.debugger_active = False
            return
        
        debug_event = DEBUG_EVENT()
        self.continue_status = DBG_CONTINUE
        
        if WaitForDebugEvent(ct.byref(debug_event), INFINITE):
            self.__loop += 1
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            if self.h_thread:
                debug_event_index = debug_event.dwDebugEventCode
                if debug_event_index > debug_event_max:
                    debug_event_index = debug_event_max
                
                print(f'Event code: {debug_event.dwDebugEventCode} '
                      f'({debug_event_array[debug_event_index]}) '
                      f'Thread ID: {debug_event.dwThreadId}')
                
                match debug_event.dwDebugEventCode:
                    case dd.EXCEPTION_DEBUG_EVENT:
                        self.exception_event_handler(debug_event)
                    case _:
                        print('Not yet handled')
                        
            else:
                self.debugger_active = False
            
            ContinueDebugEvent(debug_event.dwProcessId,
                               debug_event.dwThreadId,
                               self.continue_status)
    
    
    def detach(self):
        if DebugActiveProcessStop(self.pid):
            print('[*] Finished debugging. Exiting...')
            return True
        else:
            #
            # TODO: Handle failure properly.
            #
            print('There was an error.')
            return False
    
    
    def open_thread(self, thread_id):
        '''        

        Open a handle on the provided thread ID.

        Parameters
        ----------
        thread_id : HANDLE
            Thread Id on which a handle is requested.

        Returns
        -------
        Thread handle.

        '''
        h_thread = OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if not h_thread:
            #
            # TODO: Properly handle failure.
            #
            self.__error = GetLastError()
            print('[*] Unable to obtain a valid thread handle.')
            print(f'Error: 0x{self.__error:08X}')
        
        return h_thread
    
    
    def enumerate_threads(self):
        '''
        
        Enumerate the threads running inside the current process.

        Returns
        -------
        The list of running threads. If the snapshot fails None is returned.

        '''
        thread_entry = THREADENTRY32()
        thread_list = []
        
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        if snapshot is not None:
            #
            # We have to set the size of the structure, otherwise the call will fail.
            #
            thread_entry.dwSize = ct.sizeof(thread_entry)
            success = Thread32First(snapshot, ct.byref(thread_entry))
            
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = Thread32Next(snapshot, ct.byref(thread_entry))
                
            CloseHandle(snapshot)
            return thread_list
        else:
            return None
    
    
    def get_thread_context(self, thread_id):
        '''
        
        Get and return the thread CPU context.

        Parameters
        ----------
        thread_id : Thread iD
            The ID of the thread we want the CPU context.

        Returns
        -------
        A CONTEXT structure containing the thread CPU context.
        Return None in case of failure.

        '''
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        #
        # Obtain a handle to the thread.
        #
        h_thread = self.open_thread(thread_id)
        #
        # A valid thread CPU context can only be retrieved if the targeted
        # thread is suspended.
        #
        if SuspendThread(h_thread) is not INVALID_VALUE:
            if GetThreadContext(h_thread, ct.byref(context)) is None:
                context = None
            _ = ResumeThread(h_thread)
        else:
            context = None
        CloseHandle(h_thread)
        
        return context
            
        
        def read_process_memory(self, address, length):
            '''
            
            Read length data at memory address.

            Parameters
            ----------
            address : LPVOID
                Start address of the memory location to be read.
            length : ULONG
                The length of the memory location to be read.

            Returns
            -------
            data : LPVOID
                The retuned data buffer or None.

            '''
            data = ""
            read_buf = ct.create_string_buffer(length)
            count = ct.wt.DWORD(0)
            
            if not ReadProcessMemory(self.h_process,
                                     address,
                                     length,
                                     ct.byref(count)):
                return None
            else:
                data += read_buf.raw
                return data
        
        
        def write_process_memory(self, address, data):
            '''
            
            Write data at the specified data.

            Parameters
            ----------
            address : LPVOID
                Address at which the data should be writen.
            data : LPVOID
                The data to be writen.

            Returns
            -------
            bool
                DESCRIPTION.

            '''
            count = ct.wt.DWORD(0)
            length = len(data)
            c_data = ct.wt.LPVOID(data[count.value:])
            
            if not WriteProcessMemory(self.h_process,
                                      address,
                                      c_data,
                                      length,
                                      ct.byref(count)):
                return False
            else:
                return True
            
        
        def bp_set(self, address):
            '''
            
            Set a breakpoint at the provided address.

            Parameters
            ----------
            address : LPVOID
                Address at which the breakpoint could be writen.

            Returns
            -------
            bool
                True if the breakpoint as been successfully writen.

            '''
            if not self.breakpoint.has_key(address):
                try:
                    #
                    # Store the original byte
                    #
                    original_byte = self.read_process_memory(address, 1)
                    
                    #
                    # Write the INT3 opcode.
                    #
                    self.write_process_memory(address, '\xCC')
                    
                    #
                    # Register the breakpoint in our dictionary.
                    #
                    self.breakpoint[address] = {address, original_byte}
                except:
                    return False
            return True
        
        
        def func_resolve(self, dll, function):
            '''
            
            Returns the address of a function exported by the module dll.

            Parameters
            ----------
            dll : str
                The dll filename.
            function : str
                The function name.

            Returns
            -------
            The address of the exported function.

            '''
            handle = GetModuleHandle(dll)
            function_ascii = function.encode('ascii', 'ignore')
            address = GetProcAddress(handle, function_ascii)
            CloseHandle(handle)
            
            return address
            
if __name__ == "__main__":
    dbg = debugger()
    #dbg.load(r'C:\Windows\System32\notepad.exe')
    #dbg.attach(17484)
    pid = input("Enter the PID of the process to attach to: ")
    dbg.attach(int(pid))
    
    printf_address = dbg.func_resolve("msvcrt.dll", "printf")
    print(f'[*] Address of printf: 0x{printf_address:016X}')
    
    dbg.bp_set(printf_address)
    dbg.run()

