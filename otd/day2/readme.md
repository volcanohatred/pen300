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

## To look at TEB using windbf

- `dt nt!_teb`

```
0:000> dt nt!_teb
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : Ptr64 Void
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : Ptr64 Void
   +0x058 ThreadLocalStoragePointer : Ptr64 Void
   +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
   +0x068 LastErrorValue   : Uint4B
   +0x06c CountOfOwnedCriticalSections : Uint4B
   +0x070 CsrClientThread  : Ptr64 Void
   +0x078 Win32ThreadInfo  : Ptr64 Void
   +0x080 User32Reserved   : [26] Uint4B
   +0x0e8 UserReserved     : [5] Uint4B
   +0x100 WOW32Reserved    : Ptr64 Void
   +0x108 CurrentLocale    : Uint4B
   +0x10c FpSoftwareStatusRegister : Uint4B
   +0x110 ReservedForDebuggerInstrumentation : [16] Ptr64 Void
   +0x190 SystemReserved1  : [30] Ptr64 Void
   +0x280 PlaceholderCompatibilityMode : Char
   +0x281 PlaceholderHydrationAlwaysExplicit : UChar
   +0x282 PlaceholderReserved : [10] Char
   +0x28c ProxiedProcessId : Uint4B
   +0x290 _ActivationStack : _ACTIVATION_CONTEXT_STACK
   +0x2b8 WorkingOnBehalfTicket : [8] UChar
   +0x2c0 ExceptionCode    : Int4B
   +0x2c4 Padding0         : [4] UChar
   +0x2c8 ActivationContextStackPointer : Ptr64 _ACTIVATION_CONTEXT_STACK
   +0x2d0 InstrumentationCallbackSp : Uint8B
   +0x2d8 InstrumentationCallbackPreviousPc : Uint8B
   +0x2e0 InstrumentationCallbackPreviousSp : Uint8B
   +0x2e8 TxFsContext      : Uint4B
   +0x2ec InstrumentationCallbackDisabled : UChar
   +0x2ed UnalignedLoadStoreExceptions : UChar
   +0x2ee Padding1         : [2] UChar
   +0x2f0 GdiTebBatch      : _GDI_TEB_BATCH
   +0x7d8 RealClientId     : _CLIENT_ID
   +0x7e8 GdiCachedProcessHandle : Ptr64 Void
   +0x7f0 GdiClientPID     : Uint4B
   +0x7f4 GdiClientTID     : Uint4B
   +0x7f8 GdiThreadLocalInfo : Ptr64 Void
   +0x800 Win32ClientInfo  : [62] Uint8B
   +0x9f0 glDispatchTable  : [233] Ptr64 Void
   +0x1138 glReserved1      : [29] Uint8B
   +0x1220 glReserved2      : Ptr64 Void
   +0x1228 glSectionInfo    : Ptr64 Void
   +0x1230 glSection        : Ptr64 Void
   +0x1238 glTable          : Ptr64 Void
   +0x1240 glCurrentRC      : Ptr64 Void
   +0x1248 glContext        : Ptr64 Void
   +0x1250 LastStatusValue  : Uint4B
   +0x1254 Padding2         : [4] UChar
   +0x1258 StaticUnicodeString : _UNICODE_STRING
   +0x1268 StaticUnicodeBuffer : [261] Wchar
   +0x1472 Padding3         : [6] UChar
   +0x1478 DeallocationStack : Ptr64 Void
   +0x1480 TlsSlots         : [64] Ptr64 Void
   +0x1680 TlsLinks         : _LIST_ENTRY
   +0x1690 Vdm              : Ptr64 Void
   +0x1698 ReservedForNtRpc : Ptr64 Void
   +0x16a0 DbgSsReserved    : [2] Ptr64 Void
   +0x16b0 HardErrorMode    : Uint4B
   +0x16b4 Padding4         : [4] UChar
   +0x16b8 Instrumentation  : [11] Ptr64 Void
   +0x1710 ActivityId       : _GUID
   +0x1720 SubProcessTag    : Ptr64 Void
   +0x1728 PerflibData      : Ptr64 Void
   +0x1730 EtwTraceData     : Ptr64 Void
   +0x1738 WinSockData      : Ptr64 Void
   +0x1740 GdiBatchCount    : Uint4B
   +0x1744 CurrentIdealProcessor : _PROCESSOR_NUMBER
   +0x1744 IdealProcessorValue : Uint4B
   +0x1744 ReservedPad0     : UChar
   +0x1745 ReservedPad1     : UChar
   +0x1746 ReservedPad2     : UChar
   +0x1747 IdealProcessor   : UChar
   +0x1748 GuaranteedStackBytes : Uint4B
   +0x174c Padding5         : [4] UChar
   +0x1750 ReservedForPerf  : Ptr64 Void
   +0x1758 ReservedForOle   : Ptr64 Void
   +0x1760 WaitingOnLoaderLock : Uint4B
   +0x1764 Padding6         : [4] UChar
   +0x1768 SavedPriorityState : Ptr64 Void
   +0x1770 ReservedForCodeCoverage : Uint8B
   +0x1778 ThreadPoolData   : Ptr64 Void
   +0x1780 TlsExpansionSlots : Ptr64 Ptr64 Void
   +0x1788 DeallocationBStore : Ptr64 Void
   +0x1790 BStoreLimit      : Ptr64 Void
   +0x1798 MuiGeneration    : Uint4B
   +0x179c IsImpersonating  : Uint4B
   +0x17a0 NlsCache         : Ptr64 Void
   +0x17a8 pShimData        : Ptr64 Void
   +0x17b0 HeapData         : Uint4B
   +0x17b4 Padding7         : [4] UChar
   +0x17b8 CurrentTransactionHandle : Ptr64 Void
   +0x17c0 ActiveFrame      : Ptr64 _TEB_ACTIVE_FRAME
   +0x17c8 FlsData          : Ptr64 Void
   +0x17d0 PreferredLanguages : Ptr64 Void
   +0x17d8 UserPrefLanguages : Ptr64 Void
   +0x17e0 MergedPrefLanguages : Ptr64 Void
   +0x17e8 MuiImpersonation : Uint4B
   +0x17ec CrossTebFlags    : Uint2B
   +0x17ec SpareCrossTebBits : Pos 0, 16 Bits
   +0x17ee SameTebFlags     : Uint2B
   +0x17ee SafeThunkCall    : Pos 0, 1 Bit
   +0x17ee InDebugPrint     : Pos 1, 1 Bit
   +0x17ee HasFiberData     : Pos 2, 1 Bit
   +0x17ee SkipThreadAttach : Pos 3, 1 Bit
   +0x17ee WerInShipAssertCode : Pos 4, 1 Bit
   +0x17ee RanProcessInit   : Pos 5, 1 Bit
   +0x17ee ClonedThread     : Pos 6, 1 Bit
   +0x17ee SuppressDebugMsg : Pos 7, 1 Bit
   +0x17ee DisableUserStackWalk : Pos 8, 1 Bit
   +0x17ee RtlExceptionAttached : Pos 9, 1 Bit
   +0x17ee InitialThread    : Pos 10, 1 Bit
   +0x17ee SessionAware     : Pos 11, 1 Bit
   +0x17ee LoadOwner        : Pos 12, 1 Bit
   +0x17ee LoaderWorker     : Pos 13, 1 Bit
   +0x17ee SkipLoaderInit   : Pos 14, 1 Bit
   +0x17ee SpareSameTebBits : Pos 15, 1 Bit
   +0x17f0 TxnScopeEnterCallback : Ptr64 Void
   +0x17f8 TxnScopeExitCallback : Ptr64 Void
   +0x1800 TxnScopeContext  : Ptr64 Void
   +0x1808 LockCount        : Uint4B
   +0x180c WowTebOffset     : Int4B
   +0x1810 ResourceRetValue : Ptr64 Void
   +0x1818 ReservedForWdf   : Ptr64 Void
   +0x1820 ReservedForCrt   : Uint8B
   +0x1828 EffectiveContainerId : _GUID
```

we have so much information even though what windows tells us is very less.

The most important is PEB - Process environment block.

TEB is always located at [gs] secgment register and ntTib is always located at offset 0

0x00 -> ntTiB
0x60 -> PEB

Looking at PEB

`dt nt !_PEB`

0x18 -> This is Loader location. PEB_LDR

looking at information inside PEB_LDR location -

`dt nt!_PEB_LDR`

```
0:000> dt nt!_PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr64 Void
   +0x010 InLoadOrderModuleList : _LIST_ENTRY
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY
   +0x040 EntryInProgress  : Ptr64 Void
   +0x048 ShutdownInProgress : UChar
   +0x050 ShutdownThreadId : Ptr64 Void

```

THis pEB_LDR_DATA - containes information about what dll are loaded and when especially InloadOrderModuleList and inMemory, and inintialization

InMemoryOrderModuleList - is made of a different datastructure than just lust entry

```
0:000> dt nt!_LDR_DATA_TABLE_ENTRY
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
   +0x068 FlagGroup        : [4] UChar
   +0x068 Flags            : Uint4B
   +0x068 PackagedBinary   : Pos 0, 1 Bit
   +0x068 MarkedForRemoval : Pos 1, 1 Bit
   +0x068 ImageDll         : Pos 2, 1 Bit
   +0x068 LoadNotificationsSent : Pos 3, 1 Bit
   +0x068 TelemetryEntryProcessed : Pos 4, 1 Bit
   +0x068 ProcessStaticImport : Pos 5, 1 Bit
   +0x068 InLegacyLists    : Pos 6, 1 Bit
   +0x068 InIndexes        : Pos 7, 1 Bit
   +0x068 ShimDll          : Pos 8, 1 Bit
   +0x068 InExceptionTable : Pos 9, 1 Bit
   +0x068 ReservedFlags1   : Pos 10, 2 Bits
   +0x068 LoadInProgress   : Pos 12, 1 Bit
   +0x068 LoadConfigProcessed : Pos 13, 1 Bit
   +0x068 EntryProcessed   : Pos 14, 1 Bit
   +0x068 ProtectDelayLoad : Pos 15, 1 Bit
   +0x068 ReservedFlags3   : Pos 16, 2 Bits
   +0x068 DontCallForThreads : Pos 18, 1 Bit
   +0x068 ProcessAttachCalled : Pos 19, 1 Bit
   +0x068 ProcessAttachFailed : Pos 20, 1 Bit
   +0x068 CorDeferredValidate : Pos 21, 1 Bit
   +0x068 CorImage         : Pos 22, 1 Bit
   +0x068 DontRelocate     : Pos 23, 1 Bit
   +0x068 CorILOnly        : Pos 24, 1 Bit
   +0x068 ChpeImage        : Pos 25, 1 Bit
   +0x068 ReservedFlags5   : Pos 26, 2 Bits
   +0x068 Redirected       : Pos 28, 1 Bit
   +0x068 ReservedFlags6   : Pos 29, 2 Bits
   +0x068 CompatDatabaseProcessed : Pos 31, 1 Bit
   +0x06c ObsoleteLoadCount : Uint2B
   +0x06e TlsIndex         : Uint2B
   +0x070 HashLinks        : _LIST_ENTRY
   +0x080 TimeDateStamp    : Uint4B
   +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
   +0x090 Lock             : Ptr64 Void
   +0x098 DdagNode         : Ptr64 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY
   +0x0b0 LoadContext      : Ptr64 _LDRP_LOAD_CONTEXT
   +0x0b8 ParentDllBase    : Ptr64 Void
   +0x0c0 SwitchBackContext : Ptr64 Void
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : Uint8B
   +0x100 LoadTime         : _LARGE_INTEGER
   +0x108 BaseNameHashValue : Uint4B
   +0x10c LoadReason       : _LDR_DLL_LOAD_REASON
   +0x110 ImplicitPathOptions : Uint4B
   +0x114 ReferenceCount   : Uint4B
   +0x118 DependentLoadFlags : Uint4B
   +0x11c SigningLevel     : UChar
```

_LIST_ENTRY -means that they are doubly lilnked list

so structures have structures in themslves

we cannot find the memory address of loaded dll unless we have LoadLibrary, we cannot find loadlibrary unless we find kernel32.dl address.

`!teb` - to get information about Thread Environemnt Block

Client id in teb is the process id

```python
0:000> !teb
TEB at 0000006cd0536000
    ExceptionList:        0000000000000000
    StackBase:            0000006cd03d0000 # the extent of stack
    StackLimit:           0000006cd02d4000
    SubSystemTib:         0000000000000000
    FiberData:            0000000000001e00
    ArbitraryUserPointer: 0000000000000000
    Self:                 0000006cd0536000
    EnvironmentPointer:   0000000000000000
    ClientId:             0000000000001144 . 0000000000000364
    RpcHandle:            0000000000000000
    Tls Storage:          000001edc3105ee0
    PEB Address:          0000006cd0535000
    LastErrorValue:       187
    LastStatusValue:      c00700bb
    Count Owned Locks:    0
    HardErrorMode:        0
```

`r` for all the register information

```
0:000> r
rax=0000000000000000 rbx=0000000000000010 rcx=00007ffae7bed214
rdx=0000000000000000 rsi=00007ffae7c81a90 rdi=0000006cd0535000
rip=00007ffae7c206b0 rsp=0000006cd03ced80 rbp=0000000000000000
 r8=0000006cd03ced78  r9=0000000000000000 r10=0000000000000000
r11=0000000000000246 r12=0000000000000040 r13=0000000000000000
r14=00007ffae7c748f0 r15=000001edc30b0000
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!LdrpDoDebuggerBreak+0x30:
00007ffa`e7c206b0 cc              int     3
```

`~.` - information about the start of process

`!PEB` - 
```
0:000> !peb
PEB at 0000006cd0535000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes
    ImageBaseAddress:         00007ff7b6da0000
    NtGlobalFlag:             70
    NtGlobalFlag2:            0
    Ldr                       00007ffae7cba4c0
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 000001edc3102a30 . 000001edc3103150
    Ldr.InLoadOrderModuleList:           000001edc3102be0 . 000001edc3105aa0
    Ldr.InMemoryOrderModuleList:         000001edc3102bf0 . 000001edc3105ab0
                    Base TimeStamp                     Module
            7ff7b6da0000 e1cbfc53 Jan 16 01:26:43 2090 C:\Windows\System32\cmd.exe
            7ffae7b50000 a280d1d6 May 23 16:48:38 2056 C:\Windows\SYSTEM32\ntdll.dll
            7ffae60a0000 38b369c4 Feb 22 21:01:56 2000 C:\Windows\System32\KERNEL32.DLL
            7ffae5560000 0b9a844a Mar 02 20:36:26 1976 C:\Windows\System32\KERNELBASE.dll
            7ffae5c40000 564f9f39 Nov 20 14:31:21 2015 C:\Windows\System32\msvcrt.dll
            7ffae7310000 baf10630 May 21 03:32:16 2069 C:\Windows\System32\combase.dll
            7ffae5a90000 2bd748bf Apr 22 18:39:11 1993 C:\Windows\System32\ucrtbase.dll
            7ffae5e10000 9f38e81d Aug 25 14:39:41 2054 C:\Windows\System32\RPCRT4.dll
    SubSystemData:     0000000000000000
    ProcessHeap:       000001edc3100000
    ProcessParameters: 000001edc3102150
    CurrentDirectory:  'C:\Windows\system32\'
    WindowTitle:  'C:\Windows\System32\cmd.exe'
    ImageFile:    'C:\Windows\System32\cmd.exe'
    CommandLine:  'C:\Windows\System32\cmd.exe'
    DllPath:      '< Name not readable >'
    Environment:  000001edc3101130
        =::=::\
        ALLUSERSPROFILE=C:\ProgramData
        APPDATA=C:\Users\WIN10RED\AppData\Roaming
        CommonProgramFiles=C:\Program Files\Common Files
        CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
        CommonProgramW6432=C:\Program Files\Common Files
        COMPUTERNAME=DESKTOP-ATB3U19
        ComSpec=C:\Windows\system32\cmd.exe
        DBGENG_OVERRIDE_DBGSRV_PATH=C:\Users\WIN10RED\AppData\Local\Microsoft\WindowsApps\Microsoft.WinDbg_8wekyb3d8bbwe\dbgsrvX64.exe
        DBGHELP_HOMEDIR=C:\ProgramData\Dbg
        DriverData=C:\Windows\System32\Drivers\DriverData
        HOMEDRIVE=C:
        HOMEPATH=\Users\WIN10RED
        LOCALAPPDATA=C:\Users\WIN10RED\AppData\Local
        LOGONSERVER=\\DESKTOP-ATB3U19
        NUMBER_OF_PROCESSORS=2
        OneDrive=C:\Users\WIN10RED\OneDrive
        OS=Windows_NT
        Path=C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2202.7001.0_neutral__8wekyb3d8bbwe\amd64;C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2202.7001.0_neutral__8wekyb3d8bbwe\amd64;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\Git\cmd;C:\Program Files\dotnet\;C:\Users\WIN10RED\AppData\Local\Microsoft\WindowsApps;C:\Users\WIN10RED\.dotnet\tools;C:\Users\WIN10RED\AppData\Local\Programs\Microsoft VS Code\bin
        PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
        PROCESSOR_ARCHITECTURE=AMD64
        PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
        PROCESSOR_LEVEL=23
        PROCESSOR_REVISION=3100
        ProgramData=C:\ProgramData
        ProgramFiles=C:\Program Files
        ProgramFiles(x86)=C:\Program Files (x86)
        ProgramW6432=C:\Program Files
        PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        PUBLIC=C:\Users\Public
        SRCSRV_SHOW_TF_PROMPT=1
        SystemDrive=C:
        SystemRoot=C:\Windows
        TEMP=C:\Users\WIN10RED\AppData\Local\Temp
        TMP=C:\Users\WIN10RED\AppData\Local\Temp
        USERDOMAIN=DESKTOP-ATB3U19
        USERDOMAIN_ROAMINGPROFILE=DESKTOP-ATB3U19
        USERNAME=WIN10RED
        USERPROFILE=C:\Users\WIN10RED
        VS140COMNTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\
        windir=C:\Windows
```


TIB -> PEB -> LDR -> InMemoryOrderModuleList -> Dllbase

Since we know that LDR is like a PEB_LDR_DATA - so we will typecast this address as a structure.

`dt nt!_PEB_LDR_DATA address of PEB block`

```
PEB at 0000006cd0535000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes
    ImageBaseAddress:         00007ff7b6da0000
    NtGlobalFlag:             70
    NtGlobalFlag2:            0
    Ldr                       00007ffae7cba4c0 # this is the address
```

```
0:000> dt nt!_PEB_LDR_DATA 00007ffae7cba4c0
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x58
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x010 InLoadOrderModuleList : _LIST_ENTRY [ 0x000001ed`c3102be0 - 0x000001ed`c3105aa0 ]
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY [ 0x000001ed`c3102bf0 - 0x000001ed`c3105ab0 ]
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY [ 0x000001ed`c3102a30 - 0x000001ed`c3103150 ]
   +0x040 EntryInProgress  : (null) 
   +0x048 ShutdownInProgress : 0 ''
   +0x050 ShutdownThreadId : (null) 

```

Looking at memory location

1. _PEB_LDR_DATA - 00007ffae7cba4c0

- InMemoryOrderModuleList - _LIST_ENTRY [ 0x000001ed`c3102bf0 - 0x000001ed`c3105ab0 ]

2. The InMemoryOrderModuleList is of type _LDR_DATA_TABLE_ENTRY, next typecasting _LDR_DATA_TABLE_ENTRY withe the valueif InMemoryOrderModuleLust

```
0:000> dt nt!_LDR_DATA_TABLE_ENTRY 0x000001ed`c3102bf0
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x000001ed`c3102a20 - 0x00007ffa`e7cba4e0 ]
   +0x010 InMemoryOrderLinks : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x020 InInitializationOrderLinks : _LIST_ENTRY [ 0x00007ff7`b6da0000 - 0x00007ff7`b6db8f50 ]
   +0x030 DllBase          : 0x00000000`00067000 Void
   +0x038 EntryPoint       : 0x00000000`00380036 Void
   +0x040 SizeOfImage      : 0xc3102798
   +0x048 FullDllName      : _UNICODE_STRING "cmd.exe"
   +0x058 BaseDllName      : _UNICODE_STRING "ⱐ쌐ǭ"
   +0x068 FlagGroup        : [4]  " ???"
   +0x068 Flags            : 0xe7cba320
   +0x068 PackagedBinary   : 0y0
   +0x068 MarkedForRemoval : 0y0
   +0x068 ImageDll         : 0y0
   +0x068 LoadNotificationsSent : 0y0
   +0x068 TelemetryEntryProcessed : 0y0
   +0x068 ProcessStaticImport : 0y1
   +0x068 InLegacyLists    : 0y0
   +0x068 InIndexes        : 0y0
   +0x068 ShimDll          : 0y1
   +0x068 InExceptionTable : 0y1
   +0x068 ReservedFlags1   : 0y00
   +0x068 LoadInProgress   : 0y0
   +0x068 LoadConfigProcessed : 0y1
   +0x068 EntryProcessed   : 0y0
   +0x068 ProtectDelayLoad : 0y1
   +0x068 ReservedFlags3   : 0y11
   +0x068 DontCallForThreads : 0y0
   +0x068 ProcessAttachCalled : 0y1
   +0x068 ProcessAttachFailed : 0y0
   +0x068 CorDeferredValidate : 0y0
   +0x068 CorImage         : 0y1
   +0x068 DontRelocate     : 0y1
   +0x068 CorILOnly        : 0y1
   +0x068 ChpeImage        : 0y1
   +0x068 ReservedFlags5   : 0y01
   +0x068 Redirected       : 0y0
   +0x068 ReservedFlags6   : 0y11
   +0x068 CompatDatabaseProcessed : 0y1
   +0x06c ObsoleteLoadCount : 0x7ffa
   +0x06e TlsIndex         : 0
   +0x070 HashLinks        : _LIST_ENTRY [ 0x00000000`e1cbfc53 - 0x00000000`00000000 ]
   +0x080 TimeDateStamp    : 0
   +0x088 EntryPointActivationContext : 0x000001ed`c3102d30 _ACTIVATION_CONTEXT
   +0x090 Lock             : 0x000001ed`c3102d30 Void
   +0x098 DdagNode         : 0x000001ed`c3102d30 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY [ 0x0000006c`d03cf070 - 0x00000000`00000000 ]
   +0x0b0 LoadContext      : 0x00007ffa`e7c6c3a4 _LDRP_LOAD_CONTEXT
   +0x0b8 ParentDllBase    : (null) 
   +0x0c0 SwitchBackContext : (null) 
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : 0x00000004`41eaadfe
   +0x100 LoadTime         : _LARGE_INTEGER 0x00000002`00000000
   +0x108 BaseNameHashValue : 0
   +0x10c LoadReason       : 0 ( LoadReasonStaticDependency )
   +0x110 ImplicitPathOptions : 0xabababab
   +0x114 ReferenceCount   : 0xabababab
   +0x118 DependentLoadFlags : 0xabababab
   +0x11c SigningLevel     : 0xab ''
```

Doing it one more time, this time with InLoadOrderLinks - 

```
0:000> dt nt!_LDR_DATA_TABLE_ENTRY 0x000001ed`c3102a20
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x000001ed`c3103140 - 0x000001ed`c3102bf0 ]
   +0x010 InMemoryOrderLinks : _LIST_ENTRY [ 0x000001ed`c3103830 - 0x00007ffa`e7cba4f0 ]
   +0x020 InInitializationOrderLinks : _LIST_ENTRY [ 0x00007ffa`e7b50000 - 0x00000000`00000000 ]
   +0x030 DllBase          : 0x00000000`001f5000 Void
   +0x038 EntryPoint       : 0x00000000`003c003a Void
   +0x040 SizeOfImage      : 0xc31028a0
   +0x048 FullDllName      : _UNICODE_STRING "ntdll.dll"
   +0x058 BaseDllName      : _UNICODE_STRING "???"
   +0x068 FlagGroup        : [4]  "???"
   +0x068 Flags            : 0xe7cba280
   +0x068 PackagedBinary   : 0y0
   +0x068 MarkedForRemoval : 0y0
   +0x068 ImageDll         : 0y0
   +0x068 LoadNotificationsSent : 0y0
   +0x068 TelemetryEntryProcessed : 0y0
   +0x068 ProcessStaticImport : 0y0
   +0x068 InLegacyLists    : 0y0
   +0x068 InIndexes        : 0y1
   +0x068 ShimDll          : 0y0
   +0x068 InExceptionTable : 0y1
   +0x068 ReservedFlags1   : 0y00
   +0x068 LoadInProgress   : 0y0
   +0x068 LoadConfigProcessed : 0y1
   +0x068 EntryProcessed   : 0y0
   +0x068 ProtectDelayLoad : 0y1
   +0x068 ReservedFlags3   : 0y11
   +0x068 DontCallForThreads : 0y0
   +0x068 ProcessAttachCalled : 0y1
   +0x068 ProcessAttachFailed : 0y0
   +0x068 CorDeferredValidate : 0y0
   +0x068 CorImage         : 0y1
   +0x068 DontRelocate     : 0y1
   +0x068 CorILOnly        : 0y1
   +0x068 ChpeImage        : 0y1
   +0x068 ReservedFlags5   : 0y01
   +0x068 Redirected       : 0y0
   +0x068 ReservedFlags6   : 0y11
   +0x068 CompatDatabaseProcessed : 0y1
   +0x06c ObsoleteLoadCount : 0x7ffa
   +0x06e TlsIndex         : 0
   +0x070 HashLinks        : _LIST_ENTRY [ 0x00000000`a280d1d6 - 0x00000000`00000000 ]
   +0x080 TimeDateStamp    : 0
   +0x088 EntryPointActivationContext : 0x000001ed`c3102b60 _ACTIVATION_CONTEXT
   +0x090 Lock             : 0x000001ed`c3102b60 Void
   +0x098 DdagNode         : 0x000001ed`c3102b60 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x0b0 LoadContext      : (null) 
   +0x0b8 ParentDllBase    : 0x000001ed`c3105118 Void
   +0x0c0 SwitchBackContext : (null) 
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : 0xf46857d4
   +0x100 LoadTime         : _LARGE_INTEGER 0x00000002`00000000
   +0x108 BaseNameHashValue : 0x800
   +0x10c LoadReason       : 0 ( LoadReasonStaticDependency )
   +0x110 ImplicitPathOptions : 0xabababab
   +0x114 ReferenceCount   : 0xabababab
   +0x118 DependentLoadFlags : 0xabababab
   +0x11c SigningLevel     : 0xab ''

```
One more time with loadOrder links

```
0:000> dt nt!_LDR_DATA_TABLE_ENTRY 0x000001ed`c3103140
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x000001ed`c3103820 - 0x000001ed`c3102a20 ]
   +0x010 InMemoryOrderLinks : _LIST_ENTRY [ 0x00007ffa`e7cba4f0 - 0x000001ed`c3103830 ]
   +0x020 InInitializationOrderLinks : _LIST_ENTRY [ 0x00007ffa`e60a0000 - 0x00007ffa`e60b70d0 ]
   +0x030 DllBase          : 0x00000000`000be000 Void
   +0x038 EntryPoint       : 0x00000000`00420040 Void
   +0x040 SizeOfImage      : 0xc3103300
   +0x048 FullDllName      : _UNICODE_STRING "KERNEL32.DLL"
   +0x058 BaseDllName      : _UNICODE_STRING "ㆠ쌐ǭ"
   +0x068 FlagGroup        : [4]  "`???"
   +0x068 Flags            : 0xe7cba260
   +0x068 PackagedBinary   : 0y0
   +0x068 MarkedForRemoval : 0y0
   +0x068 ImageDll         : 0y0
   +0x068 LoadNotificationsSent : 0y0
   +0x068 TelemetryEntryProcessed : 0y0
   +0x068 ProcessStaticImport : 0y1
   +0x068 InLegacyLists    : 0y1
   +0x068 InIndexes        : 0y0
   +0x068 ShimDll          : 0y0
   +0x068 InExceptionTable : 0y1
   +0x068 ReservedFlags1   : 0y00
   +0x068 LoadInProgress   : 0y0
   +0x068 LoadConfigProcessed : 0y1
   +0x068 EntryProcessed   : 0y0
   +0x068 ProtectDelayLoad : 0y1
   +0x068 ReservedFlags3   : 0y11
   +0x068 DontCallForThreads : 0y0
   +0x068 ProcessAttachCalled : 0y1
   +0x068 ProcessAttachFailed : 0y0
   +0x068 CorDeferredValidate : 0y0
   +0x068 CorImage         : 0y1
   +0x068 DontRelocate     : 0y1
   +0x068 CorILOnly        : 0y1
   +0x068 ChpeImage        : 0y1
   +0x068 ReservedFlags5   : 0y01
   +0x068 Redirected       : 0y0
   +0x068 ReservedFlags6   : 0y11
   +0x068 CompatDatabaseProcessed : 0y1
   +0x06c ObsoleteLoadCount : 0x7ffa
   +0x06e TlsIndex         : 0
   +0x070 HashLinks        : _LIST_ENTRY [ 0x00000000`38b369c4 - 0x00000000`00000000 ]
   +0x080 TimeDateStamp    : 0
   +0x088 EntryPointActivationContext : 0x000001ed`c3103280 _ACTIVATION_CONTEXT
   +0x090 Lock             : 0x000001ed`c3103280 Void
   +0x098 DdagNode         : 0x000001ed`c3103280 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x0b0 LoadContext      : 0x00007ffa`e7c6c3a4 _LDRP_LOAD_CONTEXT
   +0x0b8 ParentDllBase    : 0x000001ed`c31038d8 Void
   +0x0c0 SwitchBackContext : 0x000001ed`c3102ad8 Void
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : 0x00000004`536cd652
   +0x100 LoadTime         : _LARGE_INTEGER 0x00000002`00004000
   +0x108 BaseNameHashValue : 0
   +0x10c LoadReason       : 0 ( LoadReasonStaticDependency )
   +0x110 ImplicitPathOptions : 0xabababab
   +0x114 ReferenceCount   : 0xabababab
   +0x118 DependentLoadFlags : 0xabababab
   +0x11c SigningLevel     : 0xab ''

```

And we finally reach kernel32

```
0x030 DllBase          : 0x00000000`000be000
```

Once we find the address of kernel32 next we need to find how the kernel32 loads the various offsets, and use it to find address of loadlibraryA to load the dll and GetProcAddress of the function in the dll

## PE and DLL differnec

1. Executables have only imports while DLLs have both imports and exports
2. Exports are functions that the dll exposes
LoadLibraryA API - 
reads a PE file, parses and validates a header
Maps the file into memory and cast the headers to struct
Find the PE entrypoint
Execute the entrypoint

DLL linking - static, dynamuc, runtime

static - code is resolved at buildtime and the executable contains the exported code from the DLL thus larger than file. -static in gcc

dynamic lilnking - smaller in size, and contains the import directory which contain a list of DLLs -l in gcc

runtime linking - loads a DLL from disk during rutime mostly using LoadLbraryA and GetProcAddress
does not contain IAT. no flags in gcc

## looking at dnamic loading a library 

get a moduel handlr to existing DLL using - LoadLibraryA and GetModuleHandle

Find the function pointer of the function you want to call from DLLs module handle

createa typedef for the function you want to call

typecast the function we want to call

and call the typecaster function pointer

attempt this program

## loading the structures












