# The source from https://pre.empt.dev/posts/bluffy/

UuidFromStringA - 
CLSIDFromString

uses uui and svg and css for static evasion of shellcode

wepaonised here : https://github.com/boku7/Ninja_UUID_Runner - this works with calc

BLuffy : https://github.com/preemptdev/bluffy

can we use uuid for static evasion?

# creating our own C2

from https://pre.empt.dev/posts/maelstrom-an-introduction/

https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc/edit#gid=04

There are a ton of design patterns, but we went with MoSCoW as its fairly straight-forward and easy to translate to GitHub tags and milestones:

The term Moscow itself is an acronym derived from the first letter (ish) of each of four prioritization categories: M - Must have, S - Should have, C - Could have, W - Won't have.

ent utility to check the entropy of each file

# writing a C2 implant
simple command intrepreter 

```C#
public void ExecuteCommand(String command)
    {
       Process p = new Process();
       ProcessStartInfo startInfo = new ProcessStartInfo();
       startInfo.FileName = "cmd.exe";
       startInfo.Arguments = @"/c " + command; // cmd.exe spesific implementation
       p.StartInfo = startInfo;
       p.Start();
    }
```

# nice reference for evasion

https://evasions.checkpoint.com/ 

# automatic techniques to bypass amsi
amsi.fail

# invoke-obfuscation - 

https://github.com/danielbohannon/Invoke-Obfuscation










