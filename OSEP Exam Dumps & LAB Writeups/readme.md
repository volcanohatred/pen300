# OSEP exam dumps

Reading through the exam dumps

# AC_BANK

encoding payload

using a # application to take the shellcode and run it

creating an c# application with virtualAllocExNUma

making an hta file

using swaks

using meterpreter listener and waiting for incoming shell

Inside C:\ProgramFiles\Setup find mail.ps1 file → obtain paul credentials (just like challenge 4)

DOwnload sharphound and enumerate domain

Run autoroute from metasploit and start socks proxy from here supplement all subsequent
commands with proxychains 

Find two SQL servers SQL05 and SQL06 that are linked. Follow Challenge_4_pdf exactly to do
the ntlm relay between them and grab the admin hashes and dump SAM
Connect to SQL05 using paul creds and dump SAM of SQL06 by ntlmrelayx
Connect to SQL06 using paul creds and dump SAM of SQL05 by ntlmrelayx
You now have local admin hash of both use evil-wirm to get proof.txt

Use same local admin hash on file05 to winrm enable RDP and disable AV → run mimikatz →
PPL protection remove → dump hashes

Get Jim password from the lsass dump and use that to evil-win-rm to jump02 → disable AV →
run mimikatz → PPL protection remove → dump hashes exactly like Step10

Also use disable restricted admin to enable rdp and then rdp using xfreerdp ben

Now swiftmgmt01 has generic write on swiftweb01 (check bloodhound)
Exploit the RBCD exactly as in lab manual, spawn powershell in a machine account context
(swiftweb01$) using mimikatz pass the hash and get code exec on swiftweb01

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resourcebased-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
Step 14:
Inside you will find a powershell script curling to a web server in a different vlan
Step15:
Insert nishang reverse shell (https://github.com/samratashok/nishang)
After receiving reverse shell port forward using chisel find port 80 for swift01
Step 16:
Command injection in webpage add powershell one liner reverse shell nishang payload and get
shell and read secret.txt

# lab1

Looking at lab1 dump I realise that first it was domain enumeration

and then look at port 90 there was a portal fo putting in word documents with job isting id

then we created a macro

amsi bypass

dropper 

we need to use 32 bit macro instead of 64 bit macro.

msfvenom and vba encryptors

bypassing amsi applocker problems

enumerating app locker rules

CLM bypass

kerberos tickets.

# lab 2


