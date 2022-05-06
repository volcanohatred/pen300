#include <Windows.h>
#include <stdio.h>


// learn about typedef of a function
//1. create a typedef for the function you want to call
typedef BOOL(WINAPI* myGetComputerNameA) (
	LPSTR lpBuffer,
	LPDWORD nSize
);

//BOOL GetComputerNameA(
//	LPSTR lpBuffer,
//	LPDWORD nSize
//); // what did we do here not required


int main() {
    //2. getting the module handle of an existing dll from the disk
	HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
	printf("huser32: %p\n", hkernel32);
    //3. find the function pointer of the function we want to call rom DLL's module handle
	//4.  and typecast the function
    myGetComputerNameA getCompName = (myGetComputerNameA)GetProcAddress(hkernel32, "GetComputerNameA");
   	printf("msgbox address: %p\n", getCompName);
	// here we are getting the address of GetComputerNameA, and then putting it in a myGetComputerNameA.

    //5. call the typecasted function
	if (getCompName != NULL) {
		CHAR hostName[260];
		DWORD hostNameLength = 260;
		if (getCompName(hostName, &hostNameLength)) {
			printf("hostname : %s\n", hostName);
		}
	}
	
}