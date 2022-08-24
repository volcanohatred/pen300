# trying to develop tools for OSEP from various other github resources and my own

https://github.com/Octoberfest7/OSEP-Tools

https://github.com/deletehead/pen_300_osep_prep

### for learning c#

https://github.com/mvelazc0/defcon27_csharp_workshop

https://cryptopals.com/

# What You Should Also Learn By Yourself 
Although PEN-300 is fairly modern, it still misses out on some of the latest developments. Additionally, it only mentions tools like BloodHound in passing but doesn’t teach you how to use it, which seems like a big omission. As such, I think you should bolster your PEN-300 knowledge with these:

BloodHound: Pretty much essential. Learn how to collect BloodHound data with SharpHound, analyze it, and discover lateral movement vectors. PenTest Partners has a great walkthrough and includes the screenshot below.
CrackMapExec: Get familiar with this tool and integrate it into your workflow; it’ll speed up your lateral movement.
Better enumeration scripts: Although PEN-300 recommends a few, I found that I got better coverage by running a few different ones; I like JAWS for Windows and linuxprivchecker for Linux.
Other Active Directory lateral movements: HackTricks has a good list.
PenTest Partners BloodHound

Additionally, familiarize yourself with the quirks of your tooling. For example, only certain versions of Mimikatz work on Windows 10 but don’t work on others; keep multiple versions on hand in case you are dealing with a different environment.

How I Prepared for the Exam 
Given that the OSEP was a new course, I erred on the side of over-preparation:

Completed every single Extra Mile challenge
Completed all 6 course labs (do them in order from 1 to 6 as they increase in difficulty)
Completed several HackTheBox Windows boxes (see below)
Worked on the HackTheBox Cybernetics Pro Lab
I found that HTB boxes were not as useful as I expected, given that they were limited to one machine as compared to PEN-300’s focus on networks. Here are the boxes I attempted in order of usefulness (most useful first):

https://cheatsheet.haax.fr/windows-systems/privilege-escalation/

writeup at github.com/fanbyprinciple/oscp

Forest - ldap and smb enumeration, evil winrm kerberoasting and  bloodhound sharphound, dc sync password dump and psexec.exe

Active - smbmap for enumeration and smbclient to connect, gppg policy issue, kerberoasting, GetUserSPNs.py, psexec.py

Monteverde - crackmapexec password spraying, getting creds from azure.xml , using evilwinrm, privesc by getting config files which contains password for replication server.

Cascade - smb anonymous login check, rpc to list users , ldap naming contexts, getting the username and password, connecting with winrm, connecting with smb, downloading all smb files, getting a passwd, looking at groups - auditshare, getting exe, using dsnspy, getting cleartext password and use to to logon as arksvc, ad recycle bin user, using it get the files, getting password to tempadmin

Resolute - smb enumeration, e\rpclient to get the password then dnsremote admins path to get the privilege escalation.

Mantis -
Fuse
Fulcrum