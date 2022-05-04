# Day 2

# Windows internals: Thread internals

1. share the same memory space
2. Thread Environment Block (TEB)

A subset of TIB, TIB holds the data for currently running thread of the kernel

Every process for a user, is a Thread for a kernel each containing their own TIB/TEB

Contents -

Structured Exception Handling
Process ID
Thread ID
Active RPC Handle Information
Minimum Stack Bytes

WHat are TIB?

hread Information Block (TIB): Contains some information about the thread, including the list of functions that are used for error handling and much more
Thread Environment Block (TEB): Has more information about the thread, including the thread ID
Process Environment Block (PEB): Includes information about the process, such as the process name, process ID (PID...

The last thing that you need to understand related to processes and threads are these data structures (TIB, TEB, and PEB). These structures are stored inside the process memory and accessible through its code. Their main function is to include all the information about the process and each thread and make them accessible to the code so that it can easily know the process filename, the loaded DLLs, and other related information.

## Opening xdbg to look at cmd.exe

Basic attacking. File > launch executable

```python

Microsoft (R) Windows Debugger Version 10.0.22549.1000 AMD64
Copyright (c) Microsoft Corporation. All rights reserved.

CommandLine: C:\Windows\System32\cmd.exe
Symbol search path is: srv*
Executable search path is: 
ModLoad: 00007ff7`19b90000 00007ff7`19bf7000   cmd.exe 
ModLoad: 00007ffc`42830000 00007ffc`42a25000   ntdll.dll
ModLoad: 00007ffc`40910000 00007ffc`409ce000   C:\Windows\System32\KERNEL32.DLL # these loaders are loaded in different loaders
ModLoad: 00007ffc`405a0000 00007ffc`40868000   C:\Windows\System32\KERNELBASE.dll
ModLoad: 00007ffc`40f40000 00007ffc`40fde000   C:\Windows\System32\msvcrt.dll
ModLoad: 00007ffc`42480000 00007ffc`427d5000   C:\Windows\System32\combase.dll
ModLoad: 00007ffc`401a0000 00007ffc`402a0000   C:\Windows\System32\ucrtbase.dll
ModLoad: 00007ffc`41ab0000 00007ffc`41bda000   C:\Windows\System32\RPCRT4.dll
(9e0.1e08): Break instruction exception - code 80000003 (first chance)
ntdll!LdrpDoDebuggerBreak+0x30:
```

What happens in reflective dll loading is that we want the process to execute from memery itself without it touching disk.
Thus we cannot use loadlibraryA in that case to load the dll as it only loads thorugh disk we need to use a custom dll.

## Looking at kernel32.dll through cff explorer

Import library is called iit in cff explorer

so waht loadlibrary does is -
it will look for the relevant dll aand function in the dll and use getprocadress to find the actual address of the functions

and since we wont be using loadlibrar so we need to manually find the address of dll
getprocaddress will give the inital location of dll then we would need to manually find the address of other functions iwthing the dll in our custom loader


