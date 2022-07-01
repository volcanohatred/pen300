#include <stdio.h>
#include <windows.h>
#include "detours.h"
#pragma comment(lib, "user32.lib")

// pointer ot original messagebox
int (WINAPI * pOrigMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBox;

BOOL Hookem(void);
BOOL UnHookem(void);

//hooked up messagebox
int HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType){
    printf("HookedMessageBox() called. No popup on screen!\n");
    //MessageBox(NULL, "LOL message", "LOLOLOL", MB_OK);
    pOrigMessageBox(NULL, "LOL message", "LOLOLOL", MB_OK);
    return IDOK;
}

// set hooks on MessageBox
BOOL Hookem(void){
    long err;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOrigMessageBox, HookedMessageBox);
    err = DetourTransactionCommit();

    printf("Message box is hooked res= %d\n", err);
    return TRUE;
}

BOOL UnHookem(void) {
    LONG err;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread);
    DetourDetach(&(PVOID&)pOrigMessageBox, HookedMessageBox);
    err = DetourTransactionCommit();

    printf("Hook removed from MessageBox with res=%d\n", err);

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            Hookem();
            break;
        case DLL_THREAD_ATTACH:
            break;
        
        case DLL_THREAD_DETACH:
            break;
        
        case DLL_PROCESS_DETACH:
            UnHookem();
            break;
    }

    return TRUE;

}