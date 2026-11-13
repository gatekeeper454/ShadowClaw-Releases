# Copyright (c) 2026 Mike Storm. All rights reserved.
param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$ExpectedSubject,
    [Parameter(Mandatory=$true)][string]$Report
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path -LiteralPath $Directory).Path
$extensions = @('.exe', '.dll', '.msi', '.ps1', '.psm1', '.psd1')
$records = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object {
    $_.Extension.ToLowerInvariant() -in $extensions
} | Sort-Object FullName | ForEach-Object {
    $signature = Get-AuthenticodeSignature -LiteralPath $_.FullName
    if ($signature.Status -ne 'Valid') { throw 'Authenticode trust validation failed' }
    if ($signature.SignerCertificate.Subject -cne $ExpectedSubject) { throw 'Unexpected Authenticode publisher' }
    if ($null -eq $signature.TimeStamperCertificate) { throw 'RFC 3161 timestamp missing' }
    if ($signature.SignerCertificate.SignatureAlgorithm.Value -notin @(
        '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13',
        '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4'
    )) { throw 'Weak certificate signature algorithm' }
    if ($signature.SignerCertificate.PublicKey.Key.KeySize -lt 256) { throw 'Weak certificate key' }
    if ($signature.SignerCertificate.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1' -and
        $signature.SignerCertificate.PublicKey.Key.KeySize -lt 2048) { throw 'Weak RSA certificate key' }
    [ordered]@{
        path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        subject = $signature.SignerCertificate.Subject
        thumbprint = $signature.SignerCertificate.Thumbprint
        timestamp_subject = $signature.TimeStamperCertificate.Subject
    }
})
if ($records.Count -eq 0) { throw 'No Windows signing targets found' }
ConvertTo-Json -InputObject $records -Depth 5 | Set-Content -LiteralPath $Report -Encoding utf8NoBOM
