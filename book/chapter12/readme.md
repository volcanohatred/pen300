# Windows credentials

Windows implements a variety of authentication and post-authentication privilege mechanisms 
that can become quite complex in an Active Directory environment.

# Local windows Credentials

Windows can authenticate local user accounts as well as those belonging to a domain, which are 
stored within Active Directory

# SAM Database

Local Windows credentials are stored in the Security Account Manager (SAM) database670 as 
password hashes using the NTLM hashing format,671 which is based on the MD4 algorithm.

Security identifier in windows 
S-R-I-S

In this structure, the SID begins with a literal “S” to identify the string as a SID, followed by a 
revision level (usually set to “1”), an identifier-authority value (often “5”) and one or more 
subauthority values.
The subauthority will always end with a Relative Identifier (RID)675 representing a specific object 
on the machine.

Let’s use PowerShell and WMI to locate the SID of the local administrator account on our 
Windows 10 victim machine

`$env:computername`

`[wmi] "Win32_userAccount.Domain='client',Name='m'"`

not working as we need pc in domain






