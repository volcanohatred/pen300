#include <windows.h>
#include <stdio.h>


typedef int (WINAPI* myMessageBoxA)(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
);

int main() {

	HMODULE new_handle = LoadLibraryA("user32.dll");

	myMessageBoxA newMessage = (myMessageBoxA)GetProcAddress(new_handle, "MessageBoxA");
	newMessage(NULL, "FUnction called", "Dude", MB_OK);


	return 0;
}