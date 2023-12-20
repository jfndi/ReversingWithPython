# -*- coding: utf-8 -*-
"""

Creation on Wed Dec 20 11:49:19 2023

Author: kyria (Jean-François Ndi)
 
"""
import sys
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

#
# Debugger defines aliases.
#
STARTUPINFO = dd.STARTUPINFOW
PROCESS_INFORMATION = dd.PROCESS_INFORMATION

class debugger:
    def __init__(self):
        pass
    
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
        creation_flags = dd.DEBUG_PROCESS | dd.CREATE_NEW_CONSOLE
        
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
        startupinfo.wShowWindow = 0x1
        
        #
        # We then initialize the cb variable in the STARTUP_INFO struct
        # which is just the size of the struct itself.
        #
        process_information.cb = ct.sizeof(process_information)
        
        if CreateProcess(path_to_exe,
                         None,
                         None,
                         None,
                         None,
                         creation_flags,
                         None,
                         None,
                         ct.byref(startupinfo),
                         ct.byref(process_information)):
            print('[*] We have successfully launched the process!')
            print(f'[*] PID {process_information.dwProcessId}')
            
            #
            # Obtain a valid handle to the newly launched process
            # and store it for future access.
            # TODO: Properly handle failure.
            #
            self.h_process = self.open_process(process_information.dwProcessId)
        
        else:
            error = GetLastError()
            #
            # TODO: Properly handle failure.
            #
            print(f'Error: {error:08X}')
        
        
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
            h_process = OpenProcess(dd.PROCESS_ALL_ACCESS, False, pid)
            return h_process
        
        
        def attach(self, pid):
            '''
            
            Attach to a running process based on its pid.

            Parameters
            ----------
            pid : DWORD
                Target process to ba attached to.

            Returns
            -------
            None.

            '''
            #
            # TODO: Properly handle failure.
            #
            self.h_process = self.open_process(pid)
            
            #
            # We attempt to attach to the process
            # if this fails we exit the call.
            #
            if DebugActiveProcess(pid):
                self.debugger_active = True
                self.pid = pid
                self.run()
            else:
                print('[*] Unable to attach to the process')
                
                
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
        
        
        def get_debug_event(self):
            debug_event = DEBUG_EVENT()
            continue_status = DBG_CONTINUE
        
if __name__ == "__main__":
    dbg = debugger()
    dbg.load(r'C:\Windows\System32\notepad.exe')
