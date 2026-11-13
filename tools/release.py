#!/usr/bin/env python3
# Copyright (c) 2026 Mike Storm. All rights reserved.
"""Explicit-file release staging. Never check out or build private source here."""
import argparse
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile

REPOSITORY = "gatekeeper454/ShadowClaw-Releases"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
PLATFORMS = {"linux-arm64", "windows-amd64", "windows-arm64", "macos-arm64", "all"}
ROLES = {"package", "documentation", "sbom", "legal"}
MANIFEST = "release-manifest.json"
CHECKSUMS = "SHA256SUMS"
REPORT = "windows-signatures.json"
UNSIGNED_REPORT = "windows-unsigned.json"
BUNDLE = "SHA256SUMS.sigstore.json"
MAX_FILE = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * MAX_FILE
MAX_MEMBERS = 10000
SIGNABLE = {".exe", ".dll", ".msi", ".ps1", ".psm1", ".psd1"}
FORBIDDEN = {".go", ".py", ".pyc", ".c", ".cpp", ".h", ".rs", ".pdb", ".dSYM",
             ".pem", ".pfx", ".p12", ".key", ".env", ".log", ".sqlite", ".db", ".sys"}
PRIVATE_NAMES = {".git", ".github", ".aws", ".ssh", ".codex", ".agents", "node_modules",
                 "handoff.md", "agents.md", "transcripts", "staging-docs", "migration"}
LEAK = re.compile(
    rb"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|"
    rb"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    rb"AKIA[0-9A-Z]{16}|"
    rb"/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+\\|"
    rb"(?i:authorization\s*[:=]\s*[\"']?bearer\s+[A-Za-z0-9_.-]{12,})|"
    rb"(?i:(?:client_secret|api_key|access_token|password)\s*[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_./+=-]{16,}[\"'])"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def load(path):
    path = Path(path)
    require(path.stat().st_size <= 1024 * 1024, "JSON exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def write_text(path, value):
    # Checksum files are consumed on Linux/macOS even when signing on Windows.
    with Path(path).open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def safe_name(name):
    require(isinstance(name, str) and NAME.fullmatch(name) and ".." not in name,
            "Unsafe release filename")
    return name


def safe_member(name):
    require(isinstance(name, str) and len(name) <= 500 and not re.search(r"[\\:\x00-\x1f\x7f]", name),
            "Unsafe archive member")
    path = PurePosixPath(name)
    require(not path.is_absolute() and name and all(p not in {"", ".", ".."} for p in name.rstrip("/").split("/")),
            "Unsafe archive member")
    require(all(p.lower() not in PRIVATE_NAMES and not p.startswith(".") for p in path.parts),
            "Private/hidden archive member")
    require(path.suffix.lower() not in {x.lower() for x in FORBIDDEN}, "Source, debug, key or private data file rejected")
    require(not any(p.lower().endswith((".dsym", ".git")) for p in path.parts), "Private/debug directory rejected")
    # Reject Windows device names and trailing dots/spaces before cross-platform extraction.
    require(all(p == p.rstrip(" .") and p.split(".")[0].upper() not in
                {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}
                for p in path.parts), "Nonportable archive member")
    return path


def scan_stream(stream):
    tail = b""
    size = 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        require(size <= MAX_FILE, "File exceeds scan limit")
        require(not LEAK.search(tail + chunk), "Potential credential/private path detected; review locally")
        tail = chunk[-2048:]


def archive_members(path):
    """Validate all members before returning contents; never execute an uploaded file."""
    entries = []
    total = 0
    names = set()
    def check(name, size):
        nonlocal total
        safe_member(name)
        key = name.rstrip("/").casefold()
        require(key not in names, "Duplicate/case-colliding archive member")
        names.add(key)
        total += size
        require(len(names) <= MAX_MEMBERS and 0 <= size <= MAX_FILE and total <= MAX_EXPANDED,
                "Archive exceeds expansion limits")
        require(not name.lower().endswith((".zip", ".tar", ".tgz", ".tar.gz", ".7z", ".rar")),
                "Nested archives require separate release assets")
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                # zipfile normalizes backslashes on Windows and truncates NULs.
                # Validate the original stored name before either transformation.
                safe_member(member.orig_filename)
                check(member.filename, member.file_size)
                mode = member.external_attr >> 16
                require(not stat.S_ISLNK(mode) and not member.flag_bits & 1, "Linked/encrypted ZIP rejected")
                require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR}, "Special ZIP member rejected")
                if not member.is_dir():
                    with archive.open(member) as stream:
                        scan_stream(stream)
                    entries.append(member.filename)
    else:
        kinds = {}
        links = {}
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                check(member.name, member.size)
                require(member.isfile() or member.isdir() or member.issym(), "Linked/special TAR member rejected")
                kinds[member.name] = "file" if member.isfile() else "other"
                if member.issym():
                    require(not re.search(r"[\\:\x00-\x1f\x7f]", member.linkname) and not member.linkname.startswith("/"), "Unsafe TAR link target")
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname))
                    safe_member(target)
                    links[member.name] = target
                if member.isfile():
                    with archive.extractfile(member) as stream:
                        scan_stream(stream)
                    entries.append(member.name)
        for target in links.values():
            require(kinds.get(target) == "file", "Linked TAR target must be an included regular file")
    return entries


def scan_asset(path):
    safe_member(path.name)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_FILE,
            "Asset must be a nonempty regular file within limits")
    with path.open("rb") as stream:
        scan_stream(stream)
    if path.name.endswith((".zip", ".tar.gz")):
        archive_members(path)
    # Opaque MSI/DEB/RPM/PKG/DMG/PDF require manual inspection before hash approval.


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {"schema", "version", "assets"}, "Invalid manifest keys")
    require(value["schema"] == 1 and isinstance(value["version"], str) and VERSION.fullmatch(value["version"]), "Invalid version")
    require(isinstance(value["assets"], list) and 1 <= len(value["assets"]) <= 100, "Invalid asset count")
    seen = set()
    for asset in value["assets"]:
        require(isinstance(asset, dict) and set(asset) == {"name", "platform", "role", "sha256", "size"}, "Invalid asset keys")
        name = safe_name(asset["name"])
        require(name.startswith(("shadowclaw-", "ShadowClaw-")) and value["version"] in name,
                "Asset must carry the product and version")
        require(name.casefold() not in seen, "Duplicate asset")
        seen.add(name.casefold())
        require(asset["platform"] in PLATFORMS and asset["role"] in ROLES, "Invalid platform/role")
        require(isinstance(asset["sha256"], str) and HASH.fullmatch(asset["sha256"]), "Invalid asset hash")
        require(type(asset["size"]) is int and 0 < asset["size"] <= MAX_FILE, "Invalid asset size")
        suffixes = {
            "documentation": (".pdf", ".txt", ".md"), "sbom": (".spdx.json",),
            "legal": (".txt", ".md"), "package": {
                "windows-amd64": (".zip", ".exe", ".msi"), "windows-arm64": (".zip", ".exe", ".msi"),
                "linux-arm64": (".tar.gz", ".deb", ".rpm"), "macos-arm64": (".pkg", ".dmg", ".tar.gz"),
            }.get(asset["platform"], ()),
        }[asset["role"]]
        require(name.endswith(suffixes), "Unsupported asset format for platform/role")
    require(any(a["role"] == "package" for a in value["assets"]), "Release must contain a package")
    require(any(a["role"] == "sbom" for a in value["assets"]), "Release requires a public SPDX SBOM")
    require(any(a["role"] == "legal" for a in value["assets"]), "Release requires license/notice material")
    return value


def checksums(directory, manifest):
    names = [a["name"] for a in manifest["assets"]] + [MANIFEST]
    for report in (REPORT, UNSIGNED_REPORT):
        if (directory / report).exists():
            names.append(report)
    return "".join(f"{digest(directory / name)}  {name}\n" for name in sorted(names))


def refresh(directory, manifest):
    for asset in manifest["assets"]:
        path = directory / asset["name"]
        asset.update(sha256=digest(path), size=path.stat().st_size)
    validate_manifest(manifest)
    write_json(directory / MANIFEST, manifest)
    write_text(directory / CHECKSUMS, checksums(directory, manifest))


def verify(directory, expected=None):
    require(directory.is_dir() and not directory.is_symlink(), "Invalid release directory")
    require(not any(p.is_symlink() or not p.is_file() for p in directory.iterdir()), "Release directory contains nonregular files")
    if expected:
        require(HASH.fullmatch(expected) and digest(directory / MANIFEST) == expected, "Manifest approval hash mismatch")
    manifest = validate_manifest(load(directory / MANIFEST))
    allowed = {a["name"] for a in manifest["assets"]} | {MANIFEST, CHECKSUMS, REPORT, UNSIGNED_REPORT, BUNDLE}
    require({p.name for p in directory.iterdir()} <= allowed, "Unlisted release files rejected")
    for asset in manifest["assets"]:
        path = directory / asset["name"]
        require(path.stat().st_size == asset["size"] and digest(path) == asset["sha256"], "Asset hash/size mismatch")
        scan_asset(path)
    if (directory / REPORT).exists():
        with (directory / REPORT).open("rb") as stream:
            scan_stream(stream)
    if (directory / UNSIGNED_REPORT).exists():
        require(not (directory / REPORT).exists(), "Conflicting Windows signature claims")
        verify_unsigned_report(directory, manifest, load(directory / UNSIGNED_REPORT))
    require((directory / CHECKSUMS).read_text(encoding="utf-8") == checksums(directory, manifest), "Checksum inventory mismatch")
    return manifest


def stage(spec_path, output):
    spec = load(spec_path)
    require(set(spec) == {"version", "assets"}, "Invalid private staging spec")
    require(not output.exists(), "Output directory must not already exist")
    require(isinstance(spec["assets"], list) and 1 <= len(spec["assets"]) <= 100, "Invalid asset count")
    manifest = {"schema": 1, "version": spec["version"], "assets": []}
    sources = []
    for asset in spec["assets"]:
        require(isinstance(asset, dict) and set(asset) == {"path", "name", "platform", "role", "reviewed_sha256"}, "Invalid private asset keys")
        path = Path(asset["path"])
        require(path.is_absolute() and not path.is_symlink(), "Use absolute regular-file paths")
        scan_asset(path)
        sha = digest(path)
        require(sha == asset["reviewed_sha256"], "Asset differs from manually reviewed bytes")
        manifest["assets"].append({k: asset[k] for k in ("name", "platform", "role")} | {"sha256": sha, "size": path.stat().st_size})
        sources.append(path)
    validate_manifest(manifest)
    output.mkdir(parents=True)
    for asset, source in zip(manifest["assets"], sources):
        shutil.copyfile(source, output / asset["name"])
    # Check copied bytes, not just the source; private paths never enter output.
    write_json(output / MANIFEST, manifest)
    write_text(output / CHECKSUMS, checksums(output, manifest))
    verify(output)


def gh(*args, capture=True):
    return subprocess.run(["gh", *args], check=True, text=True, capture_output=capture).stdout


def draft_info(tag):
    require(tag.startswith("v") and VERSION.fullmatch(tag[1:]), "Invalid release tag")
    value = json.loads(gh("release", "view", tag, "--repo", REPOSITORY, "--json", "isDraft,assets,tagName"))
    require(value["isDraft"], "Refusing to change a published release")
    return value


def download(tag, directory, expected):
    require(not directory.exists(), "Download directory must be new")
    info = draft_info(tag)
    require(1 <= len(info["assets"]) <= 105 and sum(a["size"] for a in info["assets"]) <= 4 * MAX_FILE,
            "Draft exceeds download limits")
    for asset in info["assets"]:
        safe_name(asset["name"])
        require(asset["size"] <= MAX_FILE, "Draft asset too large")
    directory.mkdir(parents=True)
    gh("release", "download", tag, "--repo", REPOSITORY, "--dir", str(directory))
    manifest = verify(directory, expected)
    require("v" + manifest["version"] == tag, "Draft version mismatch")
    require(not any((directory / name).exists() for name in (BUNDLE, REPORT, UNSIGNED_REPORT)), "Draft was already finalized; do not re-sign it")
    return manifest


def windows_unpack(directory, output):
    manifest = verify(directory)
    require(not output.exists(), "Signing directory must be new")
    output.mkdir()
    for asset in manifest["assets"]:
        if asset["role"] != "package" or not asset["platform"].startswith("windows-"):
            continue
        source = directory / asset["name"]
        target = output / asset["name"]
        target.mkdir()
        if source.suffix == ".zip":
            archive_members(source)
            with zipfile.ZipFile(source) as archive:
                for member in archive.infolist():
                    destination = target.joinpath(*safe_member(member.filename).parts)
                    if member.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(member) as src, destination.open("xb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            shutil.copyfile(source, target / asset["name"])
    files = [p for p in output.rglob("*") if p.is_file()]
    require(any(p.suffix.lower() in SIGNABLE for p in files), "Windows package has no supported signing targets")


def verify_unsigned_report(directory, manifest, records):
    require(isinstance(records, list) and records, "Missing unsigned Windows verification report")
    expected = {}
    for asset in manifest["assets"]:
        if asset["role"] != "package" or not asset["platform"].startswith("windows-"):
            continue
        path = directory / asset["name"]
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if not member.is_dir() and PurePosixPath(member.filename).suffix.lower() in SIGNABLE:
                        expected[asset["name"] + "/" + member.filename] = hashlib.sha256(archive.read(member)).hexdigest()
        else:
            expected[asset["name"] + "/" + asset["name"]] = digest(path)
    require(len(records) == len(expected) and {record["path"] for record in records} == set(expected), "Unsigned Windows target inventory mismatch")
    for record in records:
        require(set(record) == {"path", "sha256", "authenticode"}, "Invalid unsigned Windows record")
        require(record["authenticode"] == "NotSigned" and record["sha256"] == expected[record["path"]],
                "Unsigned Windows status/hash mismatch")


def windows_unsigned(directory, report):
    manifest = verify(directory)
    verify_unsigned_report(directory, manifest, load(report))
    shutil.copyfile(report, directory / UNSIGNED_REPORT)
    write_text(directory / CHECKSUMS, checksums(directory, manifest))
    verify(directory)


def windows_pack(directory, signing, report):
    manifest = verify(directory)
    records = load(report)
    require(isinstance(records, list) and records, "Missing Windows verification report")
    targets = {p.relative_to(signing).as_posix(): p for p in signing.rglob("*") if p.is_file() and p.suffix.lower() in SIGNABLE}
    require({r["path"] for r in records} == set(targets) and len(records) == len(targets), "Windows signature inventory mismatch")
    for record in records:
        require(set(record) == {"path", "sha256", "subject", "thumbprint", "timestamp_subject"}, "Invalid signature record")
        require(digest(targets[record["path"]]) == record["sha256"] and record["subject"] and record["timestamp_subject"], "Invalid verified Windows signature")
    for asset in manifest["assets"]:
        if asset["role"] != "package" or not asset["platform"].startswith("windows-"):
            continue
        path = directory / asset["name"]
        target = signing / asset["name"]
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as original:
                contents = {m.filename: original.read(m) for m in original.infolist() if not m.is_dir()}
            require(set(contents) == {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}, "Windows package inventory changed")
            for name, data in contents.items():
                if PurePosixPath(name).suffix.lower() not in SIGNABLE:
                    require((target / name).read_bytes() == data, "Nonsignable content changed")
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(contents):
                    archive.write(target / name, name)
        else:
            shutil.copyfile(target / asset["name"], path)
    shutil.copyfile(report, directory / REPORT)
    refresh(directory, manifest)
    verify(directory)


def upload_final(tag, directory, original_hash, publish):
    manifest = verify(directory)
    require(tag == "v" + manifest["version"], "Release version mismatch")
    require((directory / BUNDLE).is_file(), "Signed checksum bundle required")
    if any(a["role"] == "package" and a["platform"].startswith("windows-") for a in manifest["assets"]):
        require((directory / REPORT).is_file() or (directory / UNSIGNED_REPORT).is_file(), "Windows trust-status report required")
    subprocess.run([
        "cosign", "verify-blob", "--bundle", str(directory / BUNDLE),
        "--certificate-identity", f"https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/heads/main",
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        str(directory / CHECKSUMS),
    ], check=True)
    # Fetch the draft again to detect edits while signing. Never update published assets.
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        download(tag, Path(temp) / "before", original_hash)
    files = sorted(str(p) for p in directory.iterdir())
    gh("release", "upload", tag, "--repo", REPOSITORY, "--clobber", *files)
    with tempfile.TemporaryDirectory() as temp:
        remote = Path(temp) / "after"
        draft_info(tag)
        gh("release", "download", tag, "--repo", REPOSITORY, "--dir", str(remote))
        verify(remote, digest(directory / MANIFEST))
        require({p.name: digest(p) for p in remote.iterdir()} == {p.name: digest(p) for p in directory.iterdir()}, "Uploaded bytes differ")
    if publish:
        draft_info(tag)
        gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["stage", "verify", "draft", "download", "windows-unpack", "windows-pack", "windows-unsigned", "upload-final"])
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--expected")
    parser.add_argument("--notes", type=Path)
    parser.add_argument("--signing", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    if args.command == "stage":
        require(args.spec and args.out, "stage requires --spec and --out")
        stage(args.spec, args.out)
        print("Approved manifest SHA-256:", digest(args.out / MANIFEST))
    elif args.command == "download":
        require(args.tag and args.out and args.expected, "download requires --tag, --out and --expected")
        value = download(args.tag, args.out, args.expected)
        windows = any(a["role"] == "package" and a["platform"].startswith("windows-") for a in value["assets"])
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write(f"windows={str(windows).lower()}\n")
    elif args.command == "windows-unpack":
        require(args.directory and args.out, "windows-unpack requires --directory and --out")
        windows_unpack(args.directory, args.out)
    elif args.command == "windows-pack":
        require(args.directory and args.signing and args.report, "windows-pack requires --directory, --signing and --report")
        windows_pack(args.directory, args.signing, args.report)
    elif args.command == "windows-unsigned":
        require(args.directory and args.report, "windows-unsigned requires --directory and --report")
        windows_unsigned(args.directory, args.report)
    elif args.command == "upload-final":
        require(args.tag and args.directory and args.expected, "upload-final requires --tag, --directory and --expected")
        upload_final(args.tag, args.directory, args.expected, args.publish)
    else:
        require(args.directory, "--directory is required")
        value = verify(args.directory, args.expected)
        if args.command == "draft":
            require(args.notes and args.notes.is_file(), "Draft requires reviewed public --notes")
            with args.notes.open("rb") as stream:
                scan_stream(stream)
            require(not any((args.directory / name).exists() for name in (BUNDLE, REPORT, UNSIGNED_REPORT)), "Use a new unsigned draft")
            branch = json.loads(gh("api", f"repos/{REPOSITORY}"))["default_branch"]
            commit = json.loads(gh("api", f"repos/{REPOSITORY}/commits/{branch}"))["sha"]
            gh("release", "create", "v" + value["version"], "--repo", REPOSITORY, "--draft", "--target", commit,
               "--title", "ShadowClaw " + value["version"], "--notes-file", str(args.notes),
               *(["--prerelease"] if "-" in value["version"] else []),
               *sorted(str(p) for p in args.directory.iterdir()), capture=False)
        else:
            print("Release inventory verified")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, tarfile.TarError, subprocess.CalledProcessError) as error:
        # Never echo file contents, credentials, or subprocess stdout/stderr.
        raise SystemExit("Release operation failed: " + (str(error) if isinstance(error, ValueError) else type(error).__name__))
