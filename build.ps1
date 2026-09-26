# Thin wrapper: build.py is the one implementation, so Windows and CI agree.
param([string]$OutName = "soterchecker", [string]$Package = "")
$call = @()
if ($OutName) { $call += @("--out", $OutName) }
if ($Package) { $call += @("--rename-package", $Package) }
python (Join-Path $PSScriptRoot "build.py") @call
exit $LASTEXITCODE

