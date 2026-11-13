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
        if ($Mode -eq 'i') {
            $zip=[IO.Path]::Combine([IO.Path]::GetDirectoryName($PackagePath),[IO.Path]::GetFileNameWithoutExtension($PackagePath).ToLowerInvariant()+'.zip')
            if (Test-Path -LiteralPath $zip) {
                $diagnostic=Join-Path $env:RUNNER_TEMP ('sc-msi-diagnostic-'+[Guid]::NewGuid().ToString('N'))
                Expand-Archive -LiteralPath $zip -DestinationPath $diagnostic
                $legacyPS=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe'
                $systemLog=Join-Path $env:RUNNER_TEMP ('system-output-'+[Guid]::NewGuid().ToString('N')+'.txt')
                $systemScript=Join-Path $env:RUNNER_TEMP ('system-check-'+[Guid]::NewGuid().ToString('N')+'.ps1')
                $payload=Join-Path $diagnostic 'Install.ps1'
                @(
                    '$ErrorActionPreference="Stop"',
                    "try { & '$payload' -Action Install *> '$systemLog' } catch { `$_ | Format-List * -Force | Out-String | Out-File '$systemLog' -Append; exit 1 }"
                ) | Set-Content -LiteralPath $systemScript
                $task='ShadowClaw-Diagnostic-'+[Guid]::NewGuid().ToString('N')
                try {
                    $action=New-ScheduledTaskAction -Execute $legacyPS -Argument ('-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$systemScript+'"')
                    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal | Out-Null
                    Start-ScheduledTask -TaskName $task
                    Start-Sleep 10
                    if (Test-Path $systemLog) { Write-Output 'SYSTEM-context diagnostic:'; Get-Content $systemLog }
                } finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue }
                Write-Output 'Diagnosing the same verified installer under native Windows PowerShell 5.1:'
                & $legacyPS -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $diagnostic 'Install.ps1') -Action Install
                Write-Output ('Diagnostic installer exit: '+$LASTEXITCODE)
                & $legacyPS -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $diagnostic 'Install.ps1') -Action Uninstall
            }
        }
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
