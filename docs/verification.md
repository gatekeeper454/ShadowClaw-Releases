# Verify a download

Download the selected assets, `release-manifest.json`, `SHA256SUMS` and
`SHA256SUMS.sigstore.json` from the **same published release**. If supplied,
also download `windows-signatures.json`. Avoid artifacts from pull requests,
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

For Windows, extract the package and check its executable/installer signatures:

```powershell
Get-AuthenticodeSignature -LiteralPath .\shadowclaw.exe |
  Format-List Status,SignerCertificate,TimeStamperCertificate
```

Require `Valid`, the publisher named in that release's notes, and a timestamp.
An external ZIP signature alone is not Authenticode. The Windows verification
report records the expected subjects and file digests inside the package.
Do not execute a package to find out whether its signature is valid.

For macOS, retain the platform's Gatekeeper, Developer ID and notarization
checks. For Linux, the Cosign signature authenticates the release inventory;
it is not an apt/dnf repository signature, an RPM signature or kernel-module
signing. Package-manager trust requires its own separately configured channel.

Release signatures attest to distribution approval and exact file bytes.
They do not assert reproducible builds or expose private build provenance.
Sigstore signing identity and transparency records are public.
