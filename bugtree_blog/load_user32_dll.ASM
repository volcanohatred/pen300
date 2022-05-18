format PE GUI 4.0

entry start  

section '.text' code readable executable


start:  
    pushad
    call    CodeStart

CodeStart:
    pop     ebp
    sub     ebp,CodeStart           ; delta offset shit
 
    mov     ebx,[FS:0x30]           ; get a pointer to the PEB
    mov     ebx,[ebx+0x0C]          ; get PEB->Ldr
    mov     ebx,[ebx+0x14]          ; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov     ebx,[ebx]               ; 2nd Entry
    mov     ebx,[ebx]               ; 3rd Entry
    mov     ebx,[ebx+0x10]          ; Get Kernel32 Base
    mov     [ebp+dwKernelBase],ebx
    add     ebx,[ebx+0x3C]          ; Start of PE header
    mov     ebx,[ebx+0x78]          ; RVA of export dir
    add     ebx,[ebp+dwKernelBase]  ; VA of export dir
    mov     [ebp+dwExportDirectory],ebx
 
    lea     edx,[ebp+api_GetProcAddress]
    mov     ecx,[ebp+len_GetProcAddress]
    call    GetFunctionAddress
    mov     [ebp+AGetProcAddressA],eax
    lea     edx,[ebp+api_LoadLibrary]
    push    edx
    push    dword [ebp+dwKernelBase]
    call    eax
    mov     [ebp+ALoadLibraryA],eax
    lea     edx,[ebp+szUser32]
    push    edx
    call    eax
    lea     edx,[ebp+api_MessageBoxA]
    push    edx
    push    eax
    mov     ebx,[ebp+AGetProcAddressA]
    call    ebx
    mov     [ebp+AMessageBoxAA],eax
 
    push    0
    lea     edx,[ebp+szTitle]
    push    edx
    lea     edx,[ebp+szMsg]
    push    edx
    push    0
    call    eax
    popad
 
    push    0xBBBBBBBB   ;OEP
    retn
 
GetFunctionAddress:
    push    ebx
    push    esi
    push    edi
 
    mov     esi, [ebp+dwExportDirectory]
    mov     esi, [esi+0x20]          ;RVA of ENT
    add     esi, [ebp+dwKernelBase]  ;VA of ENT
    xor     ebx,ebx
    cld
 
    looper:

    inc     ebx
    lodsd
    add     eax,[ebp+dwKernelBase]   ;eax now points to the string of a function
    push    esi                      ;preserve it for the outer loop
    mov     esi,eax
    mov     edi,edx
    cld
    push    ecx
    repe    cmpsb
    pop     ecx
    pop     esi
    jne     looper
 
    dec     ebx
    mov     eax,[ebp+dwExportDirectory]
    mov     eax,[eax+0x24]          ;RVA of EOT
    add     eax,[ebp+dwKernelBase]  ;VA of EOT
    movzx   eax , word [ebx*2+eax]  ;eax now holds the ordinal of our function
    mov     ebx,[ebp+dwExportDirectory]
    mov     ebx,[ebx+0x1C]          ;RVA of EAT
    add     ebx,[ebp+dwKernelBase]  ;VA of EAT
    mov     ebx,[eax*4+ebx]
    add     ebx,[ebp+dwKernelBase]
    mov     eax,ebx

    pop     edi
    pop     esi
    pop     ebx
    ret
 
section '.data' data readable writeable

szTitle            db "Caption",0
szMsg              db "Text.",0
szUser32           db "User32.dll",0
AGetProcAddressA   dd 0
api_GetProcAddress db "GetProcAddress"
len_GetProcAddress dd $-api_GetProcAddress
ALoadLibraryA      dd 0
api_LoadLibrary    db "LoadLibraryA",0
AMessageBoxAA      dd 0
api_MessageBoxA    db "MessageBoxA",0
dwKernelBase       dd 0
dwExportDirectory  dd 0
