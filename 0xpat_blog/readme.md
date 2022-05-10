# trying out 0xpat blog

## abusing com objects
https://0xpat.github.io/Abusing_COM_Objects/

Component Object Model is a Windows binary interface for inter-process communication. Communication is performed in a form of client-server interaction - a client can call methods provided by a COM object (acting as a server) by referencing the COM object by pointer or reference.

He enumerated com objects with powershell.

## Malware development basics part 1

Windows shellcodes usually use TEB (Thread Environment Block) and PEB (Process Environment Block) to find address of loaded system libraries (kernel32.dll, kernelbase.dll or ntdll.dll) and then “browse” them to find addresses of LoadLibrary and GetProcAddress functions which then can be used to locate other functions.

analysing casting the shellcode to a pointer to a function through
`(*(void(*)()) code)();`

from : https://www.codetd.com/en/article/14043929

In C a variable is declared as `int foo;`
, to declare a function we use `int foo( );` It means that the return type of the function is int. To declare a pointer we use `*foo`.

In the expression `(*(void(*)())0)()` we can see that

1. Assuming that the variable `fp` is a function pointer, we can use `(*fp)( );` to call the function, because `fp` is a function pointer, and `*fp` is the function pointed to by the pointer, so `(*fp)( );` can call the function.

2. Suppose `fp` is a pointer to a non-return value type, then the way to call it is `void (*fp)( )`, then the type of the `fp` variable is `void (*)( )`.

3. If we were to cast this type to a constant `shellcode`, then we use `( void (*)() ) shellcode`. 

4. Now that the shellcode is cast to the type, in order to call the shellcode we use
 
   `( ( void (*)() ) shellcode )();`

---------------------

Note: We can use typedef to replace the type name of the above expression

For example: `typedef void (*ff)( );` Therefore, the way to call a function can be written as: 

`(*(ff) shellcode ) ( );`

### Executing shellcode

allocate a new memory region using VirtualAlloc (or VirtualAllocEx for remote processes) Windows API function,
fill it with the shellcode bytes (e.g. with RtlCopyMemory function which is basically a memcpy wrapper),
create a new thread using CreateThread or CreateRemoteThread function, respectively.

Release mode: Before publishing our executable we should make sure to remove some artifacts from the binary. It is a good idea to discard any debugging symbols and information - this can be achieved by switching build configuration to “Release” and disabling generation of debug information (linker configuration in project properties).

## shellcode obfuscation

We can try the simplest “encryption” - apply ROT13 cipher to all bytes of embedded shellcode - so 0x41 becomes 0x54, 0xFF becomes 0x0C and so on. During execution the shellcode will get “decrypted” by substracting a value of 0x0D (13) from every byte.

however it might not help;

## signing the binary

using makecert though its old we ise New-SelfSignedCertificate.
try to use powershell to execute this.

makecert -r -pe -n "CN=Malwr CA" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv MalwrCA.pvk MalwrCA.cer

New-SelfSignedCertificate -Subject "CN=Neware CA,"

Tried the powershell command but it is too much work.makecert requires windows sdk
















