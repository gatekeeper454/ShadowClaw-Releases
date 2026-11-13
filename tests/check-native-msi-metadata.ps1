# Copyright (c) 2026 Mike Storm. All rights reserved.
$ErrorActionPreference='Stop'
$root=Join-Path $env:RUNNER_TEMP ('msi-api-fixture-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$inputFile=Join-Path $root 'fixture.msi'
$engine=New-Object -ComObject WindowsInstaller.Installer
$db=$engine.OpenDatabase($inputFile,3)
foreach ($sql in @(
 'CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL PRIMARY KEY `File`)',
 'INSERT INTO `File` (`File`,`FileName`) VALUES (''FixtureEntry'',''MsiAction.ps1'')',
 'CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)'
)) { $view=$db.OpenView($sql);$view.Execute();$view.Close();[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null }
$db.Commit();[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) | Out-Null
$priorTemp=$env:RUNNER_TEMP;$priorEnv=$env:GITHUB_ENV
try {
 $env:RUNNER_TEMP=$root;$env:GITHUB_ENV=Join-Path $root 'test-env.txt'
 & "$PSScriptRoot/../tools/normalize-windows-msi.ps1" -PackagePath $inputFile
 $fixed=Join-Path $root 'native-finalized-msi/fixture.msi'
 $db=$engine.OpenDatabase($fixed,0)
 $view=$db.OpenView('SELECT `Action`,`Type`,`Source`,`Target`,`ExtendedType` FROM `CustomAction`');$view.Execute()
 $count=0
 while ($row=$view.Fetch()) {
  $count++
  if ($row.IntegerData(2) -notin @(3106,3426) -or $row.StringData(3) -ne 'System64Folder' -or -not $row.StringData(4).Contains('[#FixtureEntry]') -or $row.IntegerData(5) -ne 0) {throw 'Native MSI action metadata is invalid.'}
 }
 if ($count -ne 3) {throw 'Native MSI action count is invalid.'}
 $view.Close();[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) | Out-Null
 Write-Output 'PASS: native MSI database rewrite and subsequent action-table read.'
} finally {
 $env:RUNNER_TEMP=$priorTemp;$env:GITHUB_ENV=$priorEnv
 [Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine) | Out-Null
}
