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
kernel32 = ct.windll.kernel32
CreateProcess = kernel32.CreateProcessW
GetLastError = kernel32.GetLastError
OpenProcess = kernel32.OpenProcess
DebugActiveProcess = kernel32.DebugActiveProcess
WaitForDebugEvent = kernel32.WaitForDebugEvent
ContinueDebugEvent = kernel32.ContinueDebugEvent
DebugActiveProcessStop = kernel32.DebugActiveProcessStop
OpenThread = kernel32.OpenThread
CreateToolHelp32Snapshot = kernel32.CreateToolHelp32Snapshot
Thread32First = kernel32.Thread32First
Thread32Next = kernel32.Thread32Next
GetThreadContext = kernel32.GetThreadContext

#
# Debugger defines aliases.
#
STARTUPINFO = dd.STARTUPINFOW
PROCESS_INFORMATION = dd.PROCESS_INFORMATION
DEBUG_EVENT = dd.DEBUG_EVENT64
DBG_CONTINUE = dd.DBG_CONTINUE
INFINITE = dd.INFINITE
DEBUG_PROCESS = dd.DEBUG_PROCESS
DEBUG_ONLY_THIS_PROCESS = dd.DEBUG_ONLY_THIS_PROCESS
CREATE_NEW_CONSOLE = dd.CREATE_NEW_CONSOLE
CREATE_SUSPENDED = dd.CREATE_SUSPENDED
PROCESS_ALL_ACCESS = dd.PROCESS_ALL_ACCESS

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
        
if __name__ == "__main__":
    dbg = debugger()
    #dbg.load(r'C:\Windows\System32\notepad.exe')
    dbg.attach(17484)
