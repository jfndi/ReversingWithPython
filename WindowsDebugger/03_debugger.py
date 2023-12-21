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

#
# Debugger defines aliases.
#
STARTUPINFO = dd.STARTUPINFOW
PROCESS_INFORMATION = dd.PROCESS_INFORMATION
DEBUG_EVENT = dd.DEBUG_EVENT64
DBG_CONTINUE = dd.DBG_CONTINUE
INFINITE = dd.INFINITE
DEBUG_PROCESS = dd.DEBUG_PROCESS
CREATE_NEW_CONSOLE = dd.CREATE_NEW_CONSOLE
CREATE_SUSPENDED = dd.CREATE_SUSPENDED

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
        creation_flags = DEBUG_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED
        
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
            if self.debug_process(process_information.dwProcessId) == False:
                #
                # TODO: Properly handle failure.
                #
                print('[*] Unable to debug process.')
        
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
        
        
        def debug_process(self, pid):
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

            '''
            if DebugActiveProcess(pid):
                self.debugger_active = True
                self.pid = pid
                self.run()
            else:
                #
                # Proprely handle failure.
                #
                print('[*] Unable to attach to the process')
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
            self.h_process = self.open_process(pid)
            
            #
            # We attempt to attach to the process
            # if this fails we exit the call.
            #
            return self.debug_process(pid)
                
                
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
    dbg.load(r'C:\Windows\System32\notepad.exe')
