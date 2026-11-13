#Requires -RunAsAdministrator
# Copyright (c) 2026 Mike Storm. All rights reserved.
# Author: Mike Storm, Distinguished Engineer, CCIE Security 13847
param([Parameter(Mandatory=$true)][string]$PackagePath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
trap { Write-Output $_.ScriptStackTrace; throw $_ }
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
    Write-Output ('Native MSI SQL: '+$Sql)
    try { $view=$db.OpenView($Sql);$view.Execute();$view.Close();[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null }
    catch {
        try { Write-Output $engine.LastErrorRecord.FormatText } catch { }
        throw
    }
}
try {
    $view=$db.OpenView('SELECT `File`,`FileName` FROM `File`');$view.Execute()
    $fileId=$null
    while ($record=$view.Fetch()) {
        if (($record.StringData(2) -split '\|')[-1] -eq 'MsiAction.ps1') { $fileId=$record.StringData(1) }
    }
    $view.Close();[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    if (-not $fileId -or $fileId -notmatch '^[A-Za-z0-9_]+$') { throw 'MSI management entry point is missing.' }
    $tables=@()
    $view=$db.OpenView('SELECT `Name` FROM `_Tables`');$view.Execute()
    while ($record=$view.Fetch()) { $tables+= $record.StringData(1) }
    $view.Close();[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    if ($tables -contains 'CustomAction') { Query 'DROP TABLE `CustomAction`';$db.Commit() }
    Query 'CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(0) LOCALIZABLE, `ExtendedType` LONG PRIMARY KEY `Action`)'
    $command='"[System64Folder]WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "[#'+$fileId+']" -Action '
    foreach ($item in @(@('SCInstallServices',3106,'Install'),@('SCRemoveServices',3106,'Uninstall'),@('SCRollbackServices',3426,'Uninstall'))) {
        $view=$db.OpenView('INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`,`ExtendedType`) VALUES (?,?,?,?,?)')
        $row=$engine.CreateRecord(5)
        $row.StringData(1)=$item[0];$row.IntegerData(2)=[int]$item[1]
        $row.StringData(3)='System64Folder';$row.StringData(4)=$command+$item[2];$row.IntegerData(5)=0
        $view.Execute($row);$view.Close()
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($row) | Out-Null
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    }
    # The native sensor also protects the shared parent of its program root.
    # MSI creates that parent first, so author the same protected ProgramSDDL.
    if (($tables -contains 'CreateFolder') -and ($tables -contains 'MsiLockPermissionsEx')) {
        Query 'DELETE FROM `MsiLockPermissionsEx` WHERE `MsiLockPermissionsEx`=''VendorACL'''
        Query 'DELETE FROM `CreateFolder` WHERE `Directory_`=''VENDORDIR'''
        Query 'INSERT INTO `CreateFolder` (`Directory_`,`Component_`) VALUES (''VENDORDIR'',''ProtectedFolder'')'
        Query 'INSERT INTO `MsiLockPermissionsEx` (`MsiLockPermissionsEx`,`LockObject`,`Table`,`SDDLText`,`Condition`) VALUES (''VendorACL'',''VENDORDIR'',''CreateFolder'',''O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'',''1'')'
    }
    if ($tables -contains 'Property') { Query 'DELETE FROM `Property` WHERE `Property`=''SHADOWCLAW_MSI_INCOMPLETE''' }
    # Update summary information through this open database; opening the same
    # file through Installer while views are alive creates a sharing conflict.
    $summary=$db.SummaryInformation(1)
    $summary.Property(9)='{'+[Guid]::NewGuid().ToString().ToUpperInvariant()+'}'
    $summary.Persist()
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) | Out-Null
    $db.Commit()
} finally { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) | Out-Null }
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine) | Out-Null
[GC]::Collect();[GC]::WaitForPendingFinalizers()
@{input_sha256=(Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant();output_sha256=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant();change='Native Windows action table and protected parent folder metadata; embedded product payload unchanged.'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'metadata-finalization.json')
'PACKAGE_ARCHIVE='+$copy | Out-File -LiteralPath $env:GITHUB_ENV -Encoding utf8 -Append
