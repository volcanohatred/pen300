# Advanced Antivirus evasion

Some antivirus rely on cloud based resources and try to use AI to detect malicious behaviour

In this module, we’ll explore the impact of Windows Defender’s implementation of AMSI on 
PowerShell and Jscript. However, in order to do this, we must inspect the code at the assembly 
level. To that end, we’ll begin with an overview of assembly and then discuss the process of 
viewing code execution through the Windows Debugger.
32-bit (x86) and 64-bit (x86_64) versions of Windows 10. 
Although the differences between these versions may be subtle to the casual user, they are 
significant at the assembly level.

The stack typically stores the content of (higher-language) variables that are of static size and 
limited scope, whereas the heap is used for dynamic memory allocation and long-runtime 
persistent memory.
32-bit versions of Windows allocate 2GB of memory space to applications, ranging from the 
memory addresses 0 to 0x7FFFFFFF. 64-bit versions of Windows, on the other hand, support 
128TB (terabytes) of memory, ranging from 0 to 0x7FFFFFFFFFFF.

![](registers_x86_x64.png) 

The call343 assembly instruction transfers 
program execution to the address of the function and places the address to execute once the 
function is complete on the top of the stack where ESP (or RSP) is pointing. Once the function is 
complete, the ret344 instruction is executed, which fetches the return address from the stack and 
restores it to EIP/RIP.

 On a 32-bit architecture, the __stdcall345 calling convention reads all 
arguments from the stack. However, the 64-bit __fastcall346 calling convention expects the first 
four arguments in RCX, RDX, R8, and R9 (in that order) and the remaining arguments on the stack.

# windbg introduction




