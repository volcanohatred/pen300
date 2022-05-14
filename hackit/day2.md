# Malware and Rats

## Windows malware naming

given by CARO

type , platfirm caphaw , vairant , suffixes

https://docs.microsoft.com/en-us/microsoft-365/security/intelligence/malware-naming?view=o365-worldwide

Hackerforum.net
xx site

RATs

Quasar (https://github.com/quasar/Quasar) - discussed
• Dc RAT (https://github.com/qwqdanchun/DcRat) - discussed
• Lime-RAT (https://github.com/NYAN-x-CAT/Lime-RAT)
• AsyncRAT (https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp)
• VanillaRAT (https://github.com/DannyTheSloth/VanillaRAT)
• EagleMonitor(https://github.com/arsium/EagleMonitorRAT)

## Shell code

a poece of code that gives a reverse connectino

shell code doesnt run-

```
#include "stdio.h"
#include "string.h"

unsigned char shellcode[] = "\xeB\x02\xBA\xC7\x93"
"\xBF\x77\xFF\xD2\xCC"
"\xE8\xF3\xFF\xFF\xFF"
"\x63\x61\x6C\x63";


int main()
{
	int* ret;
	ret = (int*)&ret + 2;
	printf("Shellcode Length is : %d\n", strlen((const char*)shellcode));
	(*ret) = (int)shellcode; // it is executed but wrong address
	return 0;
}

```

buffer overflow

other vulnerabilities - 

integer overflow
format string
race condition
memory corruption

Linux has direct access to syscall but windows uses multiple dlls to do the same










