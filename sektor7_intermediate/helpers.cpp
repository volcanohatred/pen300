#include "PEstructs.h"
#include "helpers.h"
#include <studio.h>

typedef HMODULE (WINAPI * LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = NULL;

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {
    // getting offset of PEB 
#ifdef _M_IX86
    // in 32 bit fs register has a pointer to peb
    PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
    // in 64 bit the gs register has a pointer to peb   
    PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

    // return base address of calling module
    if (sModuleName == NULL)
        return (HMODULE)(ProcEnvBlk -> ImageBaseAddress);
    
    PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY * ModuleList = NULL;

    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY * pStartListEntry = ModuleList->Flink;

    for(LIST_ENTRY * pListEntry = pStartListEntry;
                     pListEntry != ModuleLust;
                     pListEntry = pListEntry->Flink)
    {
        LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY)) ;     

        if(lstrcmpi(pEntry->BaseDllName.Buffer, sModuleName)==0)
            return (HMODULE) pEntry->DllBase;            
    }

    //otherwise
    return NULL;


}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {
    char * pbaseAddr = (char *) hMod;

    // get pointer to main headers/structures
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *)(pBaseAddr + pExportDataDir->VirtualAddress);

    //rsolve address to get export address table, table of function names and the "table of ordinals"
    DWORD *pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD * pFuncNameTbl = (DWORD *)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr-> AddressOfNameOrdinals);

    // function address we wnat to look for
    void *pProcAddr = NULL;

    // resolve function by ordinal
    if(((DWORD_PTR)sProcName >> 16)==0){
        WORD ordinal = (WORD) sProcName & 0xFFFF; // convert to word
        DWORD Base = pExportDirAddr->base; // first ordinal number

        // check if ordinal is not out of scope
        if(ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;
        
        // get the function virtual address = RVA + BaseAddr
        pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
   }
   // resolve function by name
   else {
       for (DWORD i=0; i<pExportDirAddr->NUmberOfNames; i++){
           char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];

           if(strcmp(sProcName, sTmpFuncName) == 0){
               //found, get the function virtual address = RVA + BaseAddr
               pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
               break;
           }
       }
   }

   //check if found VA is forwarded to external library function

   if((char *) pProcAddr >= (char *)pExportDirAddr && 
        (char *)pProcAddr < (char *) (pExportDirAddr + pExportDataDir-> Size)){
            char * sFwdDLL = _strdup((char *)pProcAddr)
            if(!sFwdDLL) return NULL;

            // get exeteranl function name
            char * sFwdFunction = strchr(sFwdDll, '.');
            *sFwdFunction = 0;
            sFwdFunction++;

            if(pLoadLibrarya == NULL){
                pLoadLoadLibraryA = (LoadLibrary_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
                if (pLoadLibraryA == NULL) return NULL;
            }

            HMODULE hFwd = pLoadLIbraryA(sFwdDLL);
            free(sFwdDLL);
            if(!hFwd) return NULL;

            pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
        }

    return (FARPROC) pProcAddr;
}

