@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcstarter_code.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64