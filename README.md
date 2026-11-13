# ShadowClaw releases

Official ShadowClaw distribution and release verification.

Download published installers, packages and operator documentation from
[Releases](https://github.com/gatekeeper454/ShadowClaw-Releases/releases).
Each release lists its supported platforms and includes checksums, a signed
checksum bundle, an asset manifest, an SPDX software bill of materials and
license notices. Only published releases are customer downloads.

This repository contains distribution tools and public documentation. Product
development source and its history are maintained separately. GitHub's automatic
“Source code” archives contain this distribution repository, not the product source.

Before installing, follow [Verify a download](docs/verification.md). A checksum
signature authenticates the distributed files; it does not certify runtime
behavior, claim that this repository built the application, or replace Windows
Authenticode or Apple's signing and notarization.

Windows packages are unsigned by default and use SHA-256 checksums plus the
GitHub/Cosign-signed inventory. Azure is optional. Read the
[Windows prompts and policy limitations](docs/verification.md#windows-unsigned-packages-and-expected-prompts)
before installing.

Maintainers: [Prepare and publish a release](docs/maintainers.md) and
[Optional Windows Authenticode signing](docs/windows-signing.md).

Copyright (c) 2026 Mike Storm. Distribution tools are provided under the
[Apache License 2.0](LICENSE). Product assets carry their own accompanying
license and third-party notices. Making binary downloads available does not
change those licenses.
