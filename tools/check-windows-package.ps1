#Requires -RunAsAdministrator
# Copyright (c) 2026 Mike Storm. All rights reserved.
param([Parameter(Mandatory=$true)][string]$PackageDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$installer=Join-Path $PackageDirectory 'Install.ps1'
$sensorName='ShadowClawGoPreview'
$identityName='ShadowClawEvidencePreview'
foreach ($name in @($sensorName,$identityName)) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Validation requires a fresh disposable host.' }
}
$data=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$sensorData=Join-Path $data 'ShadowClaw/Go Preview'
$identityData=Join-Path $data 'ShadowClawEvidencePreview'
$installed=$false
try {
    & $installer -Action Install
    $installed=$true
    foreach ($name in @($sensorName,$identityName)) {
        $service=Get-Service -Name $name
        if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Manual') { throw 'Fresh installation must be stopped/manual.' }
    }
    Set-Content -LiteralPath (Join-Path $sensorData 'qa-preserve.txt') -Value 'synthetic native validation'
    Set-Content -LiteralPath (Join-Path $identityData 'qa-preserve.txt') -Value 'synthetic native validation'
    & $installer -Action Enable -EnableIdentity
    Start-Sleep -Seconds 15
    foreach ($name in @($sensorName,$identityName)) {
        if ((Get-Service -Name $name).Status -ne 'Running') { throw 'A combined component did not stay running.' }
    }
    Invoke-RestMethod -Uri 'http://127.0.0.1:4319/healthz' -TimeoutSec 10 | Out-Null
    & $installer -Action Status
    & $installer -Action Disable
    foreach ($name in @($sensorName,$identityName)) {
        $service=Get-Service -Name $name
        if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Manual') { throw 'Disable did not preserve the stopped/manual state.' }
    }
    & $installer -Action Install
    & $installer -Action Uninstall
    $installed=$false
    foreach ($name in @($sensorName,$identityName)) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Combined removal left a registered service.' }
    }
    foreach ($directory in @($sensorData,$identityData)) {
        if (-not (Test-Path -LiteralPath (Join-Path $directory 'qa-preserve.txt'))) { throw 'Uninstall removed retained private data.' }
    }
    Write-Output 'Combined native installation, explicit activation, health, stop, reinstall and data-preserving removal passed.'
} finally {
    if ($installed) {
        try { & $installer -Action Disable } catch { }
        try { & $installer -Action Uninstall } catch { }
    }
}
