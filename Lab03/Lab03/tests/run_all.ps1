param([string]$Python="python",[string]$OpenSSL="openssl",[string]$Executable="")
$ErrorActionPreference="Stop"
$arguments=@("$PSScriptRoot/run_all.py","--openssl",$OpenSSL)
if($Executable) { $arguments += @("--exe",$Executable) }
& $Python @arguments
exit $LASTEXITCODE
