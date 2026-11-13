# Configure Windows signing

The Windows path is prepared but requires a Microsoft Azure Artifact Signing
account and an identity-validated **Public Trust** certificate profile. This
repository does not provision paid Azure resources or complete identity checks.
Until the account is configured, a Windows release fails before signing and
cannot be promoted by this workflow. Linux-only releases do not require Azure.

Follow Microsoft's [account and signing setup](https://learn.microsoft.com/en-us/azure/artifact-signing/)
and the official action's [OIDC instructions](https://github.com/Azure/artifact-signing-action/blob/main/docs/OIDC.md).

1. Create the signing account, complete publisher identity validation, and
   create a Public Trust certificate profile in a supported region.
2. Create a dedicated Microsoft Entra application/service principal. Assign
   **Artifact Signing Certificate Profile Signer** at the narrowest supported
   scope, preferably only the selected profile. Do not grant Subscription Owner,
   Contributor, repository access, or permission to create arbitrary signing profiles.
3. Add a federated credential with these exact values:

   | Field | Value |
   | --- | --- |
   | Issuer | `https://token.actions.githubusercontent.com` |
   | Subject | `repo:gatekeeper454/ShadowClaw-Releases:environment:release` |
   | Audience | `api://AzureADTokenExchange` |

4. In this repository's **release** environment, configure these variables
   (identifiers are not passwords; never supply a client secret or private key):

   | Variable | Value |
   | --- | --- |
   | `AZURE_CLIENT_ID` | Dedicated Entra application client ID |
   | `AZURE_TENANT_ID` | Tenant ID |
   | `AZURE_SUBSCRIPTION_ID` | Subscription holding the signing account |
   | `SIGNING_ENDPOINT` | Official regional HTTPS endpoint from the signing account |
   | `SIGNING_ACCOUNT` | Signing account name |
   | `SIGNING_PROFILE` | Validated Public Trust certificate profile name |
   | `WINDOWS_PUBLISHER_SUBJECT` | Exact certificate Subject string for the validated publisher |

5. Keep the environment restricted to `main` and require the maintainer's
   approval. Trust the **environment** identity above, not a wildcard repository
   subject. The release workflow also checks the exact repository and main ref.
6. Prepare a reviewed draft, invoke **Sign and finalize release** with publishing
   disabled, and inspect the resulting signed bytes. Certify those exact final
   packages on the supported native Windows hosts before publishing.

The workflow signs `.exe`, `.dll`, `.msi`, `.ps1`, `.psm1` and `.psd1` targets
with SHA-256 and RFC 3161 timestamps. ZIPs are inspected and extracted without
executing their contents, all supported targets are signed and verified, and
non-signable file bytes must remain unchanged during repacking. Windows driver
files are rejected; kernel signing is a different release process.

Opaque MSI files must already be assembled with correctly signed embedded
components; signing the outer installer does not sign embedded executables.
Prefer ZIP intake for executable/script signing here, or supply an installer
whose components were signed through the controlled private packaging process.

The workflow validates Windows trust status, exact publisher subject and
timestamp presence and emits a per-file signature report. This is a signing
check, not installer, service, reboot, compatibility, or security certification.
Code signing also does not guarantee immediate SmartScreen reputation.

The action dependencies and Cosign version are pinned. Review their official
security updates when updating those pins. Artifact Signing retains private
keys in Microsoft's service; this repository stores no exportable signing key.
