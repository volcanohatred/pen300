#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dbghelp.lib")

//pointer to original messageBox
int (WINAPI * pOriginMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBox;

int HookedMessageBox(HWND  hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType){
    printf("HookedMessageBox() called. No popup on screen!\n");

    pOriginMessageBox(hWnd, "you loose!", "TROLOLOLO", uType);
    return IDOK;
}

BOOL Hookem(char * dll, char * origFunc, PROC hookingFunc){

    ULONG size;
    DWORD i;
    BOOL found = FALSE;

    // getting handle to base address
    HANDLE baseAddress = GetModuleHandle(NULL);

    // import table of the main module
    PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
                                                baseAddress,
                                                TRUE,
                                                IMAGE_DIRECTORY_ENTRY_IMPORT,
                                                &size,
                                                NULL);
    
    // find the imports for the target dll
    for(i=0; i< size; i++){
        char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
        if(_stricmp(importName, dll) == 0){
            found = TRUE;
            break;
        }
    }

    if(!found)
        return FALSE;

    	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly
    PROC origFuncAddr = (PROC) GetProcAddress(GetModuleHandle(dll), origFunc);

    //search IAT
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE) baseAddress + importTbl[i].FirstThunk);

    while(thunk->u1.Function){
        PROC * currentFuncAddr = (PROC *)&thunk->u1.Function;

        //found
        if (*currentFuncAddr == origFuncAddr){
            // make sure memory is writatble
            DWORD oldProtect = 0;
            VirtualProtect((LPVOID) currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

            //set the hook
            *currentFuncAddr = (PROC)hookingFunc;

            //revert protection setting back
            VirtualProtect((LPVOID) currentFuncAddr, 4096, oldProtect, &oldProtect);

            printf("IAT function %s() hooked!\n", origFunc);
            return TRUE;
        }
        thunk++;
    }

    return FALSE;

}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
    switch(dwReason) {
        case DLL_PROCESS_ATTACH:
            Hookem("user32.dll", "MessageBoxA", (PROC)HookedMessageBox);
            break;
        
        case DLL_THREAD_ATTACH:
            break;
        
        case DLL_THREAD_DETACH:
            break;
        
        case DLL_PROCESS_DETACH:
            break;
    
    }
    return TRUE;
}