
#include "loader.h"
#include "stdio.h"

//#pragma comment(lib, "advapi32.lib")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "Test Message", "Message Box Reflected", MB_OK);
		printf("Returning this output\n");
		fflush(stdout);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}