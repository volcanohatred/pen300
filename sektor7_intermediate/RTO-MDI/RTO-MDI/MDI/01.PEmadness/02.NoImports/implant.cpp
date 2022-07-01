/*

 Red Team Operator course code template
 No imports example
 
 author: reenz0h (twitter: @sektor7net)

*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helpers.h"

#pragma comment(linker, "/entry:WinMain")


typedef BOOL (WINAPI * CreateProcessA_t)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI * WaitForSingleObject_t)(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);

typedef BOOL (WINAPI * CloseHandle_t)(
  HANDLE hObject
);

//int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	CreateProcessA_t pCreateProcessA = (CreateProcessA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateProcessA");
	WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "WaitForSingleObject");
	CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

	if (!pCreateProcessA( NULL,   // No module name
					"c:\\Windows\\System32\\notepad.exe",
					NULL,           // Process handle not inheritable
					NULL,           // Thread handle not inheritable
					FALSE,          // Set handle inheritance to FALSE
					0,              // No creation flags
					NULL,           // Use parent's environment block
					NULL,           // Use parent's starting directory 
					&si,            // Pointer to STARTUPINFO structure
					&pi )           // Pointer to PROCESS_INFORMATION structure
		    ) {
        //printf( "CreateProcess failed (%d).\n", GetLastError() );
        return -1;
	}
	pWaitForSingleObject( pi.hProcess, INFINITE );
    
	// Close process and thread handles. 
    pCloseHandle( pi.hProcess );
    pCloseHandle( pi.hThread );

	return 0;
}