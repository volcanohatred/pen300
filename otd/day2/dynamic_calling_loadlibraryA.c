#include <Windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* myGetComputerNameA) (
	LPSTR lpBuffer,
	LPDWORD nSize
);

BOOL GetComputerNameA(
	LPSTR lpBuffer,
	LPDWORD nSize
);

int main() {
	HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
	myGetComputerNameA getCompName = (myGetComputerNameA)GetProcAddress(hkernel32, "GetComputerNameA");

	if (getCompName != NULL) {
		CHAR hostName[260];
		DWORD hostNameLength = 260;
		if (getCompName(hostName, &hostNameLength)) {
			printf("hostname : %s\n", hostName);
		}
	}
	
}