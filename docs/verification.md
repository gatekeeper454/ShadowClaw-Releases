# Verify a download

Download the selected assets, `release-manifest.json`, `SHA256SUMS` and
`SHA256SUMS.sigstore.json` from the **same published release**. If supplied,
also download `windows-unsigned.json` or `windows-signatures.json`, as listed in
`SHA256SUMS`. Avoid artifacts from pull requests,
workflow test runs or other repositories.

Install [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
from its official distribution. Verify the signed inventory first:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity 'https://github.com/gatekeeper454/ShadowClaw-Releases/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

Accept only a successful signature verification against that exact repository,
workflow and branch. Verification checks the bundle's signing certificate and
Sigstore transparency evidence. Do not bypass these checks or accept a different
signer merely because its signature is valid.

Then check the downloaded bytes against the authenticated inventory. On Linux:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

On macOS use `shasum -a 256 --check SHA256SUMS` after downloading every listed
file. On Windows compare `Get-FileHash -Algorithm SHA256` for each selected asset
with its exact filename and hash in the authenticated `SHA256SUMS`. Any missing
file error is different from a hash mismatch; every asset you install must match.

## Windows: unsigned packages and expected prompts

The default Windows distribution is **unsigned with respect to Authenticode**.
It uses SHA-256 and the GitHub/Cosign-signed inventory above. Check the archive
before extracting it. In PowerShell, replace the filename with the exact asset
listed in the release:

```powershell
Get-FileHash -LiteralPath .\shadowclaw-2.0.0-windows-amd64.zip -Algorithm SHA256
Get-Content -LiteralPath .\SHA256SUMS
```

Compare all 64 hexadecimal characters with the entry for that exact filename;
letter case does not matter. A hash comparison establishes a match to the
published bytes. Verifying the Cosign signature first authenticates the
inventory's release-workflow identity. Neither check removes Windows warnings.
`windows-unsigned.json` records the hashes and `NotSigned` status of executable,
installer and supported PowerShell files inside the package. It is covered by
the signed checksum inventory.

SmartScreen may show **Windows protected your PC** for an unrecognized download.
After verifying the release and deciding to trust it, users can normally select
**More info → Run anyway** when that option is available. Administrative
installation may separately prompt for elevation and show an unknown publisher.
[Microsoft's SmartScreen guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).

Windows 11 **Smart App Control** can block an unrecognized unsigned application
without an individual-app override. Enterprise application-control, SmartScreen
or PowerShell policies can also prevent installation/execution. Follow the
organization's approved deployment process on managed devices; a checksum or
Cosign signature does not override those policies.
[Smart App Control FAQ](https://support.microsoft.com/en-gb/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions),
[PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).

### Optional Authenticode-signed releases

If a release explicitly supplies Authenticode-signed Windows files, check them:

```powershell
Get-AuthenticodeSignature -LiteralPath .\shadowclaw.exe |
  Format-List Status,SignerCertificate,TimeStamperCertificate
```

For that signed variant, require `Valid`, the stated publisher and a timestamp.
`windows-signatures.json` records the expected subjects and per-file hashes.
For the default unsigned variant, `NotSigned` is expected. An external checksum
signature does not provide a Windows-verified publisher name. Do not execute
any package merely to determine its trust status.

For macOS, retain the platform's Gatekeeper, Developer ID and notarization
checks. For Linux, the Cosign signature authenticates the release inventory;
it is not an apt/dnf repository signature, an RPM signature or kernel-module
signing. Package-manager trust requires its own separately configured channel.

Release signatures attest to distribution approval and exact file bytes.
They do not assert reproducible builds or expose private build provenance.
Sigstore signing identity and transparency records are public.
