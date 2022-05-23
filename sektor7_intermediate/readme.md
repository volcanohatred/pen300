# video 4

How a loader finds the function exported by a dll.

Loader gets the PE header of the dll, gets to the export directory

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


in order to find the an exported function

we loop around AddressOfNames, find the string that matches, then look at the index of the string, check the address at the index in AddressOfNameOrdinals and go to the address in address of functions.

### looking at kernel32 with PE Bear

optional header, data directory, export functions

# video 5

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

all of them can be found in wininit.h




