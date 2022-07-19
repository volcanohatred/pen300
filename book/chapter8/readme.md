# Application whitelisting

This explores application whitelisting and living off the land
(LOLBINS and LOLBAS techniques)

# Application whitelisting theory and setup

Application whitelist is difficult to manage as a scale. 

typical applications include
1. kernel mode filter drivers
2. native kernel APIs

# Application whitelisting Theory

The native Microsoft whitelisting implementation leverages a kernel-mode filter driver and various 
native kernel APIs.
Specifically, the Microsoft kernel-mode PsSetCreateProcessNotifyRoutineEx422 API registers a 
notification callback which allows the execution of a provided kernel-mode function every time a 
new process is created. Application whitelisting software uses a custom driver to register a 
callback function through this API. This callback is then invoked every time a new process is 
created and it allows the whitelisting software to determine whether or not the application is 
whitelisted

If the software determines that the application is allowed process creation completes and the code will execute. On the other hand if the application is not allowed process will terminate.

microsoft uses Applocker

which include kernel mode driver APPID.SYS and APPIDSVC user mode service. 

APPIDSVC manages the whitelisting ruleset and identifies application when they are run based on the callback notifications form APPID.SYS

latest whitelisting solution is WDAC (WIndows Defender Application Control WDAC) which produces whitelisting actions in both user mode and kernel mode

# AppLocker setup and rules

There are three primary AppLocker rule categories, which can be combined as needed. The first 
and most simple rule is based on file paths.430 This rule can be used to whitelist a single file based 
on its filename and path or recursively include the contents of a directory.

The second rule type is based on a file hash431 which may allow a single file to execute regardless 
of the location. To avoid collisions, AppLocker uses a SHA256 Authenticode hash.

The third rule type is based on a digital signature,432 which Microsoft refers to as a publisher. This 
rule could whitelist all files from an individual publisher with a single signature, which simplifies 
whitelisting across version updates

we can launch gpedit.msc, which is the GPO configuration manager

In the local group policy editor
In the Local Group Policy Editor, we’ll navigate to Local Computer Policy -> Computer 
Configuration -> Windows Settings -> Security Settings -> Application Control Policies and select 
the AppLocker item

configure rules
enfore all and selection default rules to enable whitelisting protection.

after updating rules

we use

`gpupdate /force` to enforce the rules.

we can `copy C:\Windows\System32\calc.exe calc2.exe`



