$dir = '.'
$paths = Get-ChildItem -Recurse -directory $dir |% {$_.FullName}
Write-Output $paths
Foreach($path in $paths)  
   {  
         Invoke-Command {icacls.exe $path} >> take7.txt
    }   