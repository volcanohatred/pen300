@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccombined.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64