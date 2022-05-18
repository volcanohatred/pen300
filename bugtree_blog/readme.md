# 1 message box shellcode 

https://marcosvalle.github.io/re/exploit/2019/01/19/messagebox-shellcode.

### steps - 

Obtain the kernel32.dll base address
Find the address of GetProcAddress function
Use GetProcAddress to find the address of LoadLibrary function
Use LoadLibrary to load a DLL (such as user32.dll)
Use GetProcAddress to find the address of a function (such as MessageBox)
Specify the function parameters
Call the function

### using user32.dll using LoadLibraryA

Steps -
1. put the address of loadlibrarayA into a register 
2. put the string user32.dll into th estack
3. save address of to beginning of the string user32.dll into a register 
push ebx
call eax

The asm code will get a message box directly


