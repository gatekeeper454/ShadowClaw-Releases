# Prepare and publish a release

## Boundary

Keep source, plans, transcripts, tenant exports, development credentials and
test evidence in private development storage. This repository receives only
explicitly reviewed product assets and public notes. It has no credential to
read or write a private development repository, and no workflow fetches one.
Never add this repository as a push remote to a development checkout, fork a
development repository into it, mirror Git refs, or copy a development directory.

Build privately. Use path-trimmed release builds and inspect compiler/VCS/module
metadata, debug files, embedded configuration, dependency notices, SBOM fields,
and archive contents for unintended disclosure. Compiled code can be reverse
engineered; do not put runtime secrets in it. Public Actions logs, file names,
certificate subjects and Sigstore transparency records must be treated as public.

The tooling blocks common source/debug/key files, credential patterns, private
home paths, linked/hidden files, nested archives, path traversal and excessive
archive expansion. This is defense in depth, not proof that an asset is safe.
Manually inspect opaque MSI/DEB/RPM/PKG/DMG/PDF contents and their extracted
payloads in a suitable private environment. ZIP/TAR inspection has finite limits
and deliberately rejects links and nested archives. Do not weaken these checks
to upload a development/source bundle.

## Stage explicitly selected bytes

Use Python 3.9+ locally and the GitHub CLI. Prepare a private JSON specification
outside this repository. Each asset requires the SHA-256 of the exact bytes
you reviewed for public distribution. The following is the specification shape;
replace the sample paths and hashes with actual reviewed release files:

```json
{
  "version": "2.0.0",
  "assets": [
    {
      "path": "/absolute/private/release/shadowclaw-2.0.0-linux-arm64.tar.gz",
      "name": "shadowclaw-2.0.0-linux-arm64.tar.gz",
      "platform": "linux-arm64",
      "role": "package",
      "reviewed_sha256": "REPLACE_WITH_REVIEWED_SHA256"
    },
    {
      "path": "/absolute/private/release/shadowclaw-2.0.0.spdx.json",
      "name": "shadowclaw-2.0.0.spdx.json",
      "platform": "all",
      "role": "sbom",
      "reviewed_sha256": "REPLACE_WITH_REVIEWED_SHA256"
    },
    {
      "path": "/absolute/private/release/shadowclaw-2.0.0-NOTICES.txt",
      "name": "shadowclaw-2.0.0-NOTICES.txt",
      "platform": "all",
      "role": "legal",
      "reviewed_sha256": "REPLACE_WITH_REVIEWED_SHA256"
    }
  ]
}
```

Supported platform identifiers are `linux-arm64`, `windows-amd64`,
`windows-arm64`, `macos-arm64`, and `all` for shared documents/notices/SBOMs.
Use roles `package`, `documentation`, `sbom`, or `legal`. A release requires
at least one package, a public SPDX JSON SBOM and legal material. Tooling checks
the SBOM's inventory/hash, not its semantic completeness; produce and validate
the SBOM privately against the shipped code/dependencies. Public SBOMs must
retain required dependency/license disclosures while omitting private build paths.

```sh
python tools/release.py stage --spec /absolute/private/intake.private.json --out staged
python tools/release.py verify --directory staged
```

Staging copies only named files into a new directory. Its public manifest
contains names, platforms, roles, sizes and hashes; local input paths are removed.
Keep the printed **manifest SHA-256** for workflow approval. Review the staged
files and separate public release notes before uploading.

Use a fine-grained GitHub token limited to **this release repository** with
Contents read/write (and Actions write only if dispatching through the CLI).
Store it in a private credential manager or supply `GH_TOKEN` transiently;
never paste it into source, notes, a specification, or a shell command history.
The public workflow uses its own short-lived `GITHUB_TOKEN`, scoped to this
repository. No private-source token or deploy key belongs here.

```sh
python tools/release.py draft --directory staged --notes /absolute/private/public-release-notes.md
```

This creates a draft in the fixed release repository. It never chooses another
repository from user input, overwrites an existing release, or pushes source.
The release tag targets this distribution repository's commit. Do not represent
that tag as the application's private source commit or as build provenance.

## Sign, verify and promote

In Actions, run **Sign and finalize release** on **main**. Supply the version
without `v`, the reviewed manifest SHA-256 and the desired publish setting.
Publishing defaults to **false**. Approve the protected **release** environment.

The workflow downloads only the selected draft, verifies the approval digest
and complete inventory, signs Windows targets when present, then signs the
final checksum inventory using Cosign and GitHub OIDC. The signed inventory
covers the final assets, public manifest and Windows signature report when
present. No application build provenance is invented for uploaded binaries.

With publishing disabled, retrieve the signed draft's bytes and run final native
acceptance against them. After those gates pass, publish that existing signed
draft through GitHub's release UI. Do **not** rerun signing: it changes the
Windows package bytes and would invalidate acceptance of the earlier hashes.
If native acceptance has already qualified these exact final bytes and you
intend immediate publication, select publish in the initial workflow run.

Published releases are immutable: assets and their tags cannot be edited after
publication. Publish a new version for a correction. The workflow refuses to
alter a published or already finalized draft. A failed partial upload remains
a draft; inspect/recover it manually and reapprove its exact inventory rather
than bypassing verification. Release notes and titles are not covered by
`SHA256SUMS`; put every security-relevant downloadable file in the manifest.

Before promotion, follow [download verification](verification.md), check all
native platform gates for the **signed final bytes**, and confirm accurate
platform support, publisher identity and licensing. Do not attach source archives,
private verification records or tenant data. Historical releases in other
channels keep their original identities and bytes.

## Repository administration

Keep the repository independent (no parent/fork relationship), only grant
maintainer write access, and keep the `main` branch protected from force pushes
and deletion with passing validation checks. The `release` environment must
require maintainer approval and allow deployments only from `main`. A solo
maintainer may approve their own dispatch; this is an explicit checkpoint,
not independent two-person approval. Restrict Actions to the pinned official
checkout/Python, Azure login/signing and Sigstore installer actions used here.
Do not use self-hosted runners or execute uploaded programs/scripts in release jobs.

The original development repository must remain private. Any previously public
copies/forks cannot be recalled by repository visibility settings. No visibility
change to a development repository is required for this distribution channel.

The manual **Check release signing** workflow exercises OIDC/Cosign on synthetic
text and confirms altered bytes are rejected. It publishes no product package
or release. Its signer identity is deliberately different from the production
release workflow and must never be accepted for a product download.
