# Speccterops powershell training

https://raw.githubusercontent.com/specterops/at-ps/master/Adversary%20Tactics%20-%20PowerShell.pdf

# powershell

PowerShell itself is actually System.Management.Automation.dll
which is a dependency of various hosts (like powershell.exe)
• Other “official” script hosts exist, some of which we’ll cover later in the day
• In fact, ANY .NET application can utilize System.Management.Automation
to easily build a PowerShell pipeline runner, covered later today

we can downgrade powershell with pwershell.exe -Version 2

### Determining installed versions

(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\*\PowerShellEngine -Name PowerShellVersion).PowerShellVersion

### Execution Policy

A perception remains that execution policy is a security protection that prevernts unsigned scripts from being loaded

powershell.exe -exec bypass
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/

.ps1 = powershell script
.psm1 = a powershell module file
.psd1 = a powershell module manifest
.ps1xml = an object formatting file

Get-Command
Get-Help

Get-member - to get object

$p = Get-Process notepad
• $p | gm -force

to know overloaded function dont add () to functions
$p = Get-Process notepad
$p.CloseMainWindow

### pipeline

powerhsell cmdlets return completet objects in the pipeline

`Get-Process notepad | stop-Process -Force`

Write-host breaks the pipeline

### PSDrives

A pointer to a data structure that is managed by something called PSProvider
    Get0PSProvider. Get-PSDrive

Get-Help Get-PSDrive

### PowerShell Profiles









