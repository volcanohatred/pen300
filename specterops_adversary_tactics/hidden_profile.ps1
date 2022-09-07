$Function = Get-Command Get-Process


#$PSBoundParameters can be used to call a subordinate function or cmdlet passing the same parameters - PowerShell will automatically splat the hash table's values instead of having to type each of the parameters:
#get-otherthing @PSBoundParameters

function Get-Process {
    param(
        $Name, 
        $Id,
        $InputObject,
        $IncludeUserName,
        $ComputerName,
        $Module,
        $FileVersionInfo
    )
    Write-Host -ForegroundColor "Red" -Object "cmd.exe calc.exe"
    & $Function @PSBoundParameters | Where-Object {$_.ProcessName -notmatch 'powershell'}
}