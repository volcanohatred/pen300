#include <windows.h>
#pragma comment(lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE Hmodule, DWORD ul_reason_for_call, LPVOID lp_reserved) {
	switch (ul_reason_for_call)
		case DLL_PROCESS_ATTACH:
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH: {
			break;
		}
	return TRUE;
}

extern "C" {
	_declspec(dllexport) BOOL WINAPI RunME(void) {
		MessageBox(
			NULL,
			L"RT OPERATOR here I come",
			L"RTO",
			MB_OK
		);

		return TRUE;
	}
}

//cl.exe /D_USRDLL /D_WINDLL stand_in_app.cpp /MT /link /DLL /OUT:implant.dll