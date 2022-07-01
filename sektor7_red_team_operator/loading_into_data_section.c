#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payload[] = {
	0x90,
	0x90,
	0xcc,
	0xc3
};

unsigned int payload_len = 4;

int main(void) {

	LPVOID exec_mem;
	bool rv;
	HANDLE th;
	DWORD oldprotect = 0;

	//Allocate a memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//printf("%x addr of payload\n", &payload);
	//printf("%x exec memory address\n", exec_mem);

	//copy memory to buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

	// make a new buffer as executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	//printf("\nHit me!\n");
	getchar();

	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}

	return 0;

}