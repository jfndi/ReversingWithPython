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

class debugger:
    def __init__(self):
        self.__error = 0


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
    
    
    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if WaitForDebugEvent(ct.byref(debug_event), INFINITE):
            #
            # No event handlers for the time being.
            # Let's resume the process for now.
            #
            input('Press any key to continue: ')
            self.debugger_active = False
            ContinueDebugEvent(debug_event.dwProcessId,
                               debug_event.dwThreadId,
                               continue_status)
    
    
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
        if SuspendThread(h_thread) is not INVALID_VALUE:
            if GetThreadContext(h_thread, ct.byref(context)) is None:
                context = None
            ResumeThread(h_thread)
        else:
            context = None
        CloseHandle(h_thread)
        
        return context
            
        
        
if __name__ == "__main__":
    dbg = debugger()
    #dbg.load(r'C:\Windows\System32\notepad.exe')
    #dbg.attach(17484)
    pid = input("Enter the PID of the process to attach to: ")
    
    dbg.attach(int(pid))
    
    list = dbg.enumerate_threads()
    
    #
    # For each thread in the list we want to display
    # the general registers.
    #
    for thread in list:
        thread_context = dbg.get_thread_context(thread)
        
        print(f'[*] Dumping general registers for thread ID 0x{thread:08X}')
        if thread_context is not None:
            print(f'[**] RIP: 0x{thread_context.Rip:016X}')
            print(f'[**] RSP: 0x{thread_context.Rsp:016X}')
            print(f'[**] RBP: 0x{thread_context.Rbp:016X}')
            print(f'[**] RAX: 0x{thread_context.Rax:016X}')
            print(f'[**] RBX: 0x{thread_context.Rbx:016X}')
            print(f'[**] RCX: 0x{thread_context.Rcx:016X}')
            print(f'[**] RDX: 0x{thread_context.Rdx:016X}')
            print(f'[**] RSI: 0x{thread_context.Rsi:016X}')
            print(f'[**] RDI: 0x{thread_context.Rdi:016X}')
            print(f'[**] R8:  0x{thread_context.Rip:016X}')
            print(f'[**] R9:  0x{thread_context.Rip:016X}')
            print(f'[**] R10: 0x{thread_context.Rip:016X}')
            print(f'[**] R11: 0x{thread_context.Rip:016X}')
            print(f'[**] R12: 0x{thread_context.Rip:016X}')
            print(f'[**] R14: 0x{thread_context.Rip:016X}')
            print(f'[**] R15: 0x{thread_context.Rip:016X}')
            print(f'[**] RIP: 0x{thread_context.Rip:016X}')
        else:
            print('[*] Invalid context returned.')
        print('[*] END DUMP')
        
        