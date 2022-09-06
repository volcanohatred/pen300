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

Scripts that run every time an “official” PowerShell host (meaning
powershell.exe/powershell_ise.exe) starts
• Meant for shell customization
• Not loaded with remoting!
• i.e. the PowerShell version of /etc/profile
• You can check your current profile with $profile
• Profiles can be subverted with malicious proxy functionality!
• More information: http://www.exploitmonday.com/2015/11/investigating-subversive-powershell.html
• More information: Get-Help about_Profiles

%windir%\System32\WindowsPowerShell\v1.0\profile.ps1

# exporting and importing powershell objects

function... | Export-Clixml output.xml exports an XML-based
representation of one or more objects that can later be reimported with Import-CliXML

# Variables

$ followed by any combination of numbers and (case-insensitive)
letters
• If using New-Variable, you can specify non-printable characters!
• New-Variable -Name ([Char] 7) -Value 'foo'
• To see more information about all of the automatic variables (like
$ENV) run Get-Help about_Automatic_Variables
• If you want to list all of the variables in your current scope:
• Get-ChildItem Variable:\
• To cast a variable to a specific type, use [Type] $Var





