param([string]$Compiler="g++",[string]$OpenSSLRoot="",[string]$BuildDir="build",[string]$Python="python")
$ErrorActionPreference="Stop"
$configure=@("-S",$PSScriptRoot,"-B",(Join-Path $PSScriptRoot $BuildDir),"-G","MinGW Makefiles","-DCMAKE_CXX_COMPILER=$Compiler","-DCMAKE_BUILD_TYPE=Release","-DPython3_EXECUTABLE=$Python")
if($OpenSSLRoot) { $configure += "-DOPENSSL_ROOT_DIR=$OpenSSLRoot" }
& cmake @configure
if($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cmake --build (Join-Path $PSScriptRoot $BuildDir) --parallel 4
if($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot "$BuildDir/lab03.exe") version
exit $LASTEXITCODE
