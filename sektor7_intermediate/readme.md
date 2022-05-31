# sektor techniques

1. using custom function
2. using process injection
3. using encryption for payload and function name


# video 4

Lookinng at the functions exported by a dll.

Loader gets the PE header information of the dll, gets to the export directory
```
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name; // name of the dll
    DWORD Base; // first ordinal number
    DWORD NUmberOfFunctions // number of functions in the EXPORT ADDRESS TABLE (EAT)
    DWORD NumberOfNames // Number of entries in (1) (2)
    DWORD AddressOfFunctions // export address function
    DWORD AddressOfNames // pointer to names
    DWORD AddressOfNameOrdinals //array of index to eat


} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY

```
in order to find the an exported function

we loop around AddressOfNames, find the string that matches, then look at the index of the string, check the address at the index in AddressOfNameOrdinals and go to the address in address of functions.

addressOfNamedOrdinals contains the address of the where the particular function is loaded.  

### looking at kernel32 with PE Bear

optional header, data directory, export functions

if you go to the address pointed by rhe export directory, then at that location you will find the strings.
![](kernel32_String.png)

We can look at exports to see everything parsed.

withou using pe bear we can also use dumpbin
`dumpbin /exports C:/Windows/System32/kernel32.dll `
  

# video 5

The relationship between import lookup table > hint name  < import address table

whenever the dll is loaded into memory it will look for imports in the import lookup table and then look at hints wheneveer the function is found it updates address in import address table. its a bit confusing in video actually.

firstthunk points ot import address table

in pe bear you can look at any process, in imports tab you can look at the what dlls are loaded and then in those dll you can look at firstthunk to look at the lookup table address.

 
```
typedef struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk; // RVA of import lookup tbl  
    } DUMMYUNIONNAME;

    DWORD TimeStampStamp;
    DWORD ForwarderChain;
    DWORD Name;                     // name of imported dll
    DWORD FirstThunk;               //RVA of imported address tbl 
} IMAGE_IMPORT_DESCRIPTOR;
```

all of them can be found in winnt.h
 
need to go back to this.

# video 6

Things to try
try using array method to hide the function name - tried
add vm check - not checked
use process injection - this worked

The problem was with the way the functions we were trying to define virtually- done

starter code is ready

Now we need to define our own functions for getprocaddress and gemodulehandle.

TEB and PEB is discussed in getting getting handle to module
in wininternl.h




