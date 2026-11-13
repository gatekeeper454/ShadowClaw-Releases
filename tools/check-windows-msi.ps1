#Requires -RunAsAdministrator
# Copyright (c) 2026 Mike Storm. All rights reserved.
param([Parameter(Mandatory=$true)][string]$PackagePath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$names=@('ShadowClawGo','ShadowClawEvidence')
foreach ($name in $names) { if (Get-Service $name -ErrorAction SilentlyContinue) { throw 'Require a fresh disposable Windows host.' } }
$program=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$data=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$kit=Join-Path $program 'ShadowClaw/Installer'
$installer=Join-Path $kit 'Install.ps1'
$msiexec=Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
function MSI([string]$Mode) {
    $log=Join-Path $env:RUNNER_TEMP ('shadowclaw-msi-'+$Mode+'.log')
    $process=Start-Process -FilePath $msiexec -ArgumentList @('/'+$Mode,'"'+$PackagePath+'"','/qn','/norestart','/l*v','"'+$log+'"') -PassThru -Wait
    if ($process.ExitCode -notin @(0,3010)) {
        if (Test-Path $log) { Get-Content $log | Select-String 'Return value 3|Error |exception|failed|Failure' | Select-Object -Last 20 }
        throw "Windows Installer failed with exit code $($process.ExitCode)"
    }
}
$installed=$false
try {
    MSI i;$installed=$true
    foreach ($name in $names) {
        $service=Get-Service $name
        try {if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Manual') { throw 'Fresh release services must be stopped/manual.' }} finally {$service.Dispose()}
    }
    $sensorData=Join-Path $data 'ShadowClaw/Go'
    $identityData=Join-Path $data 'ShadowClawEvidence'
    Set-Content (Join-Path $sensorData 'qa-preserve.txt') 'synthetic retained state'
    Set-Content (Join-Path $identityData 'qa-preserve.txt') 'synthetic retained state'
    & $installer -Action Enable -EnableIdentity
    Start-Sleep 10
    foreach ($name in $names) {if ((Get-Service $name).Status -ne 'Running') {throw 'Release service did not remain running.'}}
    Invoke-RestMethod 'http://127.0.0.1:4319/healthz' -TimeoutSec 10 | Out-Null
    & $installer -Action Disable
    MSI i
    MSI x;$installed=$false
    foreach ($name in $names) {if (Get-Service $name -ErrorAction SilentlyContinue) {throw 'MSI removal left a service registered.'}}
    foreach ($directory in @($sensorData,$identityData)) {if (-not (Test-Path (Join-Path $directory 'qa-preserve.txt'))) {throw 'MSI removal deleted private data.'}}
    if (Test-Path $kit) { throw 'MSI installer payload was not removed.' }
    Write-Output 'PASS: full v2.0 MSI install, activation, repair/reinstall and data-preserving uninstall.'
} finally {if ($installed) {try {MSI x} catch {}}}
