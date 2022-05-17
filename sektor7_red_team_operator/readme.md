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






