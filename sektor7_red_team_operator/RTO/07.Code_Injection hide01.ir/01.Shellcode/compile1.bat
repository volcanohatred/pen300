@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcmanipulating_strings.cpp /link /OUT:test.exe /SUBSYSTEM:CONSOLE /MACHINE:x64