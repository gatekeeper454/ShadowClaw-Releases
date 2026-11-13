#Requires -RunAsAdministrator
# Copyright (c) 2026 Mike Storm. All rights reserved.
# Author: Mike Storm, Distinguished Engineer, CCIE Security 13847
param([Parameter(Mandatory=$true)][string]$PackagePath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# The caller first verifies the original package against the authenticated
# release inventory. Rewrite only the action table using Windows' native MSI
# database writer; preserve the original package and embedded payload stream.
$output=Join-Path $env:RUNNER_TEMP 'native-finalized-msi'
New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
$copy=Join-Path $output ([IO.Path]::GetFileName($PackagePath))
Copy-Item -LiteralPath $PackagePath -Destination $copy
$engine=New-Object -ComObject WindowsInstaller.Installer
$db=$engine.OpenDatabase($copy,1)
function Query([string]$Sql) {
    $view=$db.OpenView($Sql);$view.Execute();$view.Close()
}
try {
    $view=$db.OpenView('SELECT `File`,`FileName` FROM `File`');$view.Execute()
    $fileId=$null
    while ($record=$view.Fetch()) {
        if (($record.StringData(2) -split '\|')[-1] -eq 'MsiAction.ps1') { $fileId=$record.StringData(1) }
    }
    $view.Close()
    if (-not $fileId -or $fileId -notmatch '^[A-Za-z0-9_]+$') { throw 'MSI management entry point is missing.' }
    Query 'DROP TABLE `CustomAction`'
    Query 'CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(0) LOCALIZABLE, `ExtendedType` LONG PRIMARY KEY `Action`)'
    $command='"[System64Folder]WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "[#'+$fileId+']" -Action '
    foreach ($item in @(@('SCInstallServices',3106,'Install'),@('SCRemoveServices',3106,'Uninstall'),@('SCRollbackServices',3426,'Uninstall'))) {
        $view=$db.OpenView('INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`,`ExtendedType`) VALUES (?,?,?,?,?)')
        $row=$engine.CreateRecord(5)
        $row.StringData(1)=$item[0];$row.IntegerData(2)=[int]$item[1]
        $row.StringData(3)='System64Folder';$row.StringData(4)=$command+$item[2];$row.IntegerData(5)=0
        $view.Execute($row);$view.Close()
    }
    $db.Commit()
} finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) | Out-Null }
# Assign a fresh package code because metadata bytes changed.
$summary=$engine.SummaryInformation($copy,1)
$summary.Property(9)='{'+[Guid]::NewGuid().ToString().ToUpperInvariant()+'}'
$summary.Persist()
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) | Out-Null
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine) | Out-Null
@{input_sha256=(Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant();output_sha256=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant();change='Native Windows CustomAction table writer; embedded product payload unchanged.'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'metadata-finalization.json')
'PACKAGE_ARCHIVE='+$copy | Out-File -LiteralPath $env:GITHUB_ENV -Encoding utf8 -Append
