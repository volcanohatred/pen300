# trying out 0xpat blog

## abusing com objects
https://0xpat.github.io/Abusing_COM_Objects/

Component Object Model is a Windows binary interface for inter-process communication. Communication is performed in a form of client-server interaction - a client can call methods provided by a COM object (acting as a server) by referencing the COM object by pointer or reference.

He enumerated com objects with powershell.

# Malware development basics part 1

Windows shellcodes usually use TEB (Thread Environment Block) and PEB (Process Environment Block) to find address of loaded system libraries (kernel32.dll, kernelbase.dll or ntdll.dll) and then “browse” them to find addresses of LoadLibrary and GetProcAddress functions which then can be used to locate other functions.

analysing casting the shellcode to a pointer to a function through
`(*(void(*)()) code)();`

from : https://www.codetd.com/en/article/14043929

In C a variable is declared as `int foo;`
, to declare a function we use `int foo( );` It means that the return type of the function is int. To declare a pointer we use `*foo`.

In the expression `(*(void(*)())0)()` we can see that

1. Assuming that the variable `fp` is a function pointer, we can use `(*fp)( );` to call the function, because `fp` is a function pointer, and `*fp` is the function pointed to by the pointer, so `(*fp)( );` can call the function.

2. Suppose `fp` is a pointer to a non-return value type, then the way to call it is `void (*fp)( )`, then the type of the `fp` variable is `void (*)( )`.

3. If we were to cast this type to a constant `shellcode`, then we use `( void (*)() ) shellcode`. 

4. Now that the shellcode is cast to the type, in order to call the shellcode we use
 
   `( ( void (*)() ) shellcode )();`

---------------------

Note: We can use typedef to replace the type name of the above expression

For example: `typedef void (*ff)( );` Therefore, the way to call a function can be written as: 

`(*(ff) shellcode ) ( );`

### Executing shellcode

allocate a new memory region using VirtualAlloc (or VirtualAllocEx for remote processes) Windows API function,
fill it with the shellcode bytes (e.g. with RtlCopyMemory function which is basically a memcpy wrapper),
create a new thread using CreateThread or CreateRemoteThread function, respectively.

Release mode: Before publishing our executable we should make sure to remove some artifacts from the binary. It is a good idea to discard any debugging symbols and information - this can be achieved by switching build configuration to “Release” and disabling generation of debug information (linker configuration in project properties).

## shellcode obfuscation

We can try the simplest “encryption” - apply ROT13 cipher to all bytes of embedded shellcode - so 0x41 becomes 0x54, 0xFF becomes 0x0C and so on. During execution the shellcode will get “decrypted” by substracting a value of 0x0D (13) from every byte.

however it might not help;

can I even try and reverse a string?

## signing the binary

using makecert though its old we ise New-SelfSignedCertificate.
try to use powershell to execute this.

makecert -r -pe -n "CN=Malwr CA" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv MalwrCA.pvk MalwrCA.cer

New-SelfSignedCertificate -Subject "CN=Neware CA,"

Tried the powershell command but it is too much work.makecert requires windows sdk

# Malware development part 2 - anti dunamic analysis and sandboxes

## Hardware resources - working but virus total detection
The main problem are limited resources - a sandbox may not be able to run long and consuming simulations in parallel so is often restricts resources commited and time allocated for a single instance. Regular VM boxes used by analysts are also subject for same constraints - they often have their resources limited.
evading_edr_hardware_checks.c

## Devices and vendor names - not working
n default VM installations devices often have predictable names, for example containing strings associated with the specific hypervisor. We can check for hard drive name, optical disk drive name, BIOS version, computer manufacturer and model name, graphics controller name etc. Relevant information can be retrieved with WMI queries (check properties like “Name”, “Description”, “Caption”)
evading_edr_vmware_checks.c

## Looking for virtial devices - not working
We can also look for specific virtual devices that would not be present in a typical host system, like pipes and other interfaces used for guest-host communication:
evading_edr_virtual_machine.c

## enumerating network devices - not working
e should also pay attention to network devices. Especially MAC addresses can indicate presence of a virtual environment since first 3 bytes are manufacturer identificator by default. Let’s iterate all available network adapters and compare first bytes with well-known values

```c
DWORD adaptersListSize = 0;
	GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &adaptersListSize);
	IP_ADAPTER_ADDRESSES* pAdaptersAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, adaptersListSize);
	if (pAdaptersAddresses)
	{
		GetAdaptersAddresses(AF_UNSPEC, 0, 0, pAdaptersAddresses, &adaptersListSize);
		char mac[6] = { 0 };
		while (pAdaptersAddresses)
		{
			if (pAdaptersAddresses->PhysicalAddressLength == 6)
			{
				memcpy(mac, pAdaptersAddresses->PhysicalAddress, 6);
				if (!memcmp({ "\x08\x00\x27" }, mac, 3)) return false;
			}
			pAdaptersAddresses = pAdaptersAddresses->Next;
		}
	}
```

not able to get correct way to use #inlcude here

## VM specific artifacts

ere are also specific artifacts present on virtualized environments - files and registry entries indicating presence of a hypervisor. We can check for files and directories associated with drivers, devices and modules provided by the hypervisor and registry keys and values containing configurations or hardware description.

List of directories worth checking for these artifacts include C:\Windows\System32 and C:\Windows\System32\Drivers. Interesting registry keys are HKLM\SYSTEM\ControlSet001\Services, HKLM\HARDWARE\Description\System, HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation and others.


Devices and vendor names


# trying to reverse shellcode

//ⁿΦé



















