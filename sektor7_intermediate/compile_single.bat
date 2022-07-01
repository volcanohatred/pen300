@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp helpers.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /M  