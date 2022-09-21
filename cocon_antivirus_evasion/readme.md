### Resources

1. msdn
2. Windows Internals book 

## Concepts

Specter malware -  privilege escalation, hardware exploit

EFI & UEFI

The EFI (Extensible Firmware Interface) system partition or ESP is a partition on a data storage device (usually a hard disk drive or solid-state drive) that is used by computers having the Unified Extensible Firmware Interface (UEFI).

UEFI has microsoft backup and repair. Grub is loaded in linux

in windows BCDLOADER is loaded.
Windows\Boot\EFI - memtest.efi efi

bcdedit - cmdline for boot loader

GUID number - unique GUID

Windows prefetch - 

System, System32, SysWOW64 - windows on windows

WinSxS- What is WinSxS?
Image result for winSxs
The WinSxS folder, stores multiple copies of dll, exe, and other system files to let multiple applications run in Windows without any compatibility problem. If you browse inside, you will see what looks like a lot of duplicate files, each having the same name

Shims used to create compatiblesoftware that works in WinSXS

shims application manager to spoof the application - APPCompat Toolkit 
https://techcommunity.microsoft.com/t5/ask-the-performance-team/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your/ba-p/374947

USB - nowdays defines HID norms for usb devices which helps it to communicate with the computer

sys file for drivers

Windows defender files -
WdBoot.sys
WdFIleter.sys
WdLdr.sys

Ndis.sys - network filter driver 

mountmgr.sys

### Disable windows defender using registry
in registry
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot
wdboot- start 0  - starts at lige system

![](2022-09-21-12-48-06.png)

### Singature in windows

https://www.thewindowsclub.com/catroot-catroot2-folder-reset-windows

signature are refered to CatRoot file

on x64 signing is mandatory for drivers. 

### Looking at an executable

MZ - windows executable
Cannot execute in DOS mode - to show that the program cannot run in 64 bit
EICAR test string - 16 bit string to check for antivirus chcek

PE - portable executable

.text - code the program itself
.data - content of program / strings
IAT - import address table contains dll that are loaded
EAT - the functions exported by the prigram

IAT populated by linker. 

.sys file can have an EAT that can export

ntoskrnl.exe  - can by accessible by .sys file can access kernel function.











