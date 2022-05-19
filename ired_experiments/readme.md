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
