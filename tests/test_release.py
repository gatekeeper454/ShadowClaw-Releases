# Copyright (c) 2026 Mike Storm. All rights reserved.
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("release", Path(__file__).parents[1] / "tools/release.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class ReleaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = self.root / "private"
        self.sources.mkdir()
        self.package = self.sources / "shadowclaw-2.0.0-linux-arm64.tar.gz"
        with tarfile.open(self.package, "w:gz") as archive:
            data = b"synthetic ELF test payload"
            info = tarfile.TarInfo("bin/shadowclaw")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.sbom = self.sources / "shadowclaw-2.0.0.spdx.json"
        self.sbom.write_text('{"spdxVersion":"SPDX-2.3","name":"synthetic"}')
        self.legal = self.sources / "shadowclaw-2.0.0-LICENSE.txt"
        self.legal.write_text("Synthetic license fixture")
        self.staged = self.root / "staged"

    def private_spec(self, package=None, platform="linux-arm64"):
        assets = []
        for path, role in [(package or self.package, "package"), (self.sbom, "sbom"), (self.legal, "legal")]:
            assets.append({"path": str(path), "name": path.name, "platform": platform if role == "package" else "all",
                           "role": role, "reviewed_sha256": r.digest(path)})
        value = {"version": "2.0.0", "assets": assets}
        path = self.root / "intake.private.json"
        r.write_json(path, value)
        return path

    def stage(self):
        r.stage(self.private_spec(), self.staged)

    def test_only_explicit_files_export_and_no_private_paths(self):
        (self.sources / "sensitive-unlisted.txt").write_text("never exported")
        self.stage()
        self.assertEqual(5, len(list(self.staged.iterdir())))
        self.assertNotIn(str(self.sources), (self.staged / r.MANIFEST).read_text())
        r.verify(self.staged, r.digest(self.staged / r.MANIFEST))

    def test_changed_reviewed_bytes_rejected(self):
        spec_path = self.private_spec()
        self.legal.write_text("different bytes after review")
        with self.assertRaisesRegex(ValueError, "reviewed bytes"):
            r.stage(spec_path, self.staged)
        self.assertFalse(self.staged.exists())

    def test_public_inventories_use_portable_lf_even_on_windows(self):
        self.stage()
        for name in (r.MANIFEST, r.CHECKSUMS):
            self.assertNotIn(b"\r", (self.staged / name).read_bytes())
        r.refresh(self.staged, r.load(self.staged / r.MANIFEST))
        for name in (r.MANIFEST, r.CHECKSUMS):
            self.assertNotIn(b"\r", (self.staged / name).read_bytes())

    def test_extra_file_rejected(self):
        self.stage()
        (self.staged / "accidental-source.go").write_text("package private")
        with self.assertRaisesRegex(ValueError, "Unlisted"):
            r.verify(self.staged)

    def test_tampered_asset_and_approval_rejected(self):
        self.stage()
        with self.assertRaisesRegex(ValueError, "approval hash"):
            r.verify(self.staged, "0" * 64)
        (self.staged / self.legal.name).write_text("tampered")
        with self.assertRaisesRegex(ValueError, "hash/size"):
            r.verify(self.staged)

    def test_filename_traversal_and_case_collision_rejected(self):
        self.stage()
        manifest = r.load(self.staged / r.MANIFEST)
        manifest["assets"][0]["name"] = "../shadowclaw-2.0.0.tar.gz"
        with self.assertRaises(ValueError):
            r.validate_manifest(manifest)
        manifest = r.load(self.staged / r.MANIFEST)
        manifest["assets"].append(manifest["assets"][0].copy())
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            r.validate_manifest(manifest)

    def test_json_duplicate_keys_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            r.load(path)

    def test_zip_traversal_links_source_and_nested_archives_rejected(self):
        path = self.sources / "shadowclaw-2.0.0-windows-amd64.zip"
        for name in ["../escape", "C:/escape", "safe/../../escape", "safe\\escape", ".git/config", "src/main.go", "bin/debug.pdb", "nested.zip", "CON.txt", "trail. "]:
            with self.subTest(name=name):
                with zipfile.ZipFile(path, "w") as archive:
                    info = zipfile.ZipInfo()
                    info.filename = name
                    info.orig_filename = name
                    archive.writestr(info, b"synthetic")
                with self.assertRaises(ValueError):
                    r.archive_members(path)
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("linked")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "outside")
        with self.assertRaisesRegex(ValueError, "Linked"):
            r.archive_members(path)

    def test_tar_symlink_rejected(self):
        with tarfile.open(self.package, "w:gz") as archive:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "outside"
            archive.addfile(info)
        with self.assertRaisesRegex(ValueError, "Linked"):
            r.archive_members(self.package)

    def test_archive_expansion_limit(self):
        with patch.object(r, "MAX_EXPANDED", 1):
            with self.assertRaisesRegex(ValueError, "expansion"):
                r.archive_members(self.package)

    def test_tar_relative_link_to_included_regular_payload_is_safe(self):
        with tarfile.open(self.package, "w:gz") as archive:
            binary=tarfile.TarInfo("payload/usr/libexec/shadowclaw/shadowclaw")
            binary.size=3
            archive.addfile(binary,io.BytesIO(b"ELF"))
            link=tarfile.TarInfo("payload/usr/bin/shadowclaw")
            link.type=tarfile.SYMTYPE
            link.linkname="../libexec/shadowclaw/shadowclaw"
            archive.addfile(link)
        self.assertEqual(["payload/usr/libexec/shadowclaw/shadowclaw"],r.archive_members(self.package))

    def test_credentials_and_private_paths_not_echoed(self):
        for data in [b"ghp_" + b"a" * 30, b"-----BEGIN PRIVATE KEY-----", b"/Users/fixture/project/file", b"C:\\Users\\fixture\\private", b'api_key = "' + b"a" * 30 + b'"']:
            with self.subTest(data=data[:8]):
                with self.assertRaisesRegex(ValueError, "Potential credential/private path") as caught:
                    r.scan_stream(io.BytesIO(data))
                self.assertNotIn(data.decode(), str(caught.exception))

    def test_unsigned_bundle_blocks_upload(self):
        self.stage()
        with patch.object(r, "gh") as github:
            with self.assertRaisesRegex(ValueError, "bundle required"):
                r.upload_final("v2.0.0", self.staged, "0" * 64, True)
            github.assert_not_called()

    def test_published_release_never_modified(self):
        with patch.object(r, "gh", return_value=json.dumps({"isDraft": False})):
            with self.assertRaisesRegex(ValueError, "published"):
                r.draft_info("v2.0.0")

    def test_windows_repack_preserves_other_bytes_and_exact_targets(self):
        path = self.sources / "shadowclaw-2.0.0-windows-amd64.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("bin/shadowclaw.exe", b"MZ synthetic unsigned")
            archive.writestr("config/example.json", b"{}")
        r.stage(self.private_spec(path, "windows-amd64"), self.staged)
        signing = self.root / "signing"
        r.windows_unpack(self.staged, signing)
        executable = signing / path.name / "bin/shadowclaw.exe"
        executable.write_bytes(b"MZ synthetic signed")
        report = self.root / "report.json"
        r.write_json(report, [{"path": f"{path.name}/bin/shadowclaw.exe", "sha256": r.digest(executable),
                               "subject": "CN=fixture", "thumbprint": "fixture", "timestamp_subject": "CN=timestamp"}])
        other = signing / path.name / "config/example.json"
        other.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, "Nonsignable"):
            r.windows_pack(self.staged, signing, report)
        other.write_bytes(b"{}")
        r.windows_pack(self.staged, signing, report)
        r.verify(self.staged)
        self.assertTrue((self.staged / r.REPORT).is_file())
        with zipfile.ZipFile(self.staged / path.name) as archive:
            self.assertEqual(b"{}", archive.read("config/example.json"))
            self.assertEqual(b"MZ synthetic signed", archive.read("bin/shadowclaw.exe"))

    def test_windows_unsigned_target_missing_from_report_rejected(self):
        path = self.sources / "shadowclaw-2.0.0-windows-arm64.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("shadowclaw.exe", b"MZ synthetic")
        r.stage(self.private_spec(path, "windows-arm64"), self.staged)
        signing = self.root / "signing"
        r.windows_unpack(self.staged, signing)
        report = self.root / "report.json"
        r.write_json(report, [])
        with self.assertRaisesRegex(ValueError, "Missing Windows"):
            r.windows_pack(self.staged, signing, report)

    def test_unsigned_windows_report_covers_unchanged_payload(self):
        path = self.sources / "shadowclaw-2.0.0-windows-amd64.zip"
        payload = b"MZ synthetic unsigned"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("shadowclaw.exe", payload)
        r.stage(self.private_spec(path, "windows-amd64"), self.staged)
        original = r.digest(self.staged / path.name)
        report = self.root / "unsigned.json"
        record = {"path": path.name + "/shadowclaw.exe", "sha256": hashlib.sha256(payload).hexdigest(), "authenticode": "NotSigned"}
        r.write_json(report, [record])
        r.windows_unsigned(self.staged, report)
        self.assertEqual(original, r.digest(self.staged / path.name))
        self.assertIn(r.UNSIGNED_REPORT, (self.staged / r.CHECKSUMS).read_text())
        r.verify(self.staged)
        bad = dict(record, authenticode="Valid")
        r.write_json(report, [bad])
        with self.assertRaisesRegex(ValueError, "status/hash"):
            r.verify_unsigned_report(self.staged, r.load(self.staged / r.MANIFEST), [bad])
        with self.assertRaisesRegex(ValueError, "inventory"):
            r.verify_unsigned_report(self.staged, r.load(self.staged / r.MANIFEST), [record, record])

    @unittest.skipUnless(sys.platform == "win32", "Requires native Windows signature inspection")
    def test_native_unsigned_powershell_report_without_execution(self):
        directory = self.root / "unsigned-files"
        directory.mkdir()
        # This is inspected as data; the deliberately failing script must never run.
        (directory / "install.ps1").write_text("throw 'Uploaded payload was executed'\n")
        report = self.root / "report.json"
        command = Path(__file__).parents[1] / "tools/verify-windows.ps1"
        subprocess.run(["pwsh", "-NoProfile", "-File", str(command), "-Directory", str(directory),
                        "-Unsigned", "-Report", str(report)], check=True)
        value = r.load(report)
        self.assertEqual(1, len(value))
        self.assertEqual("NotSigned", value[0]["authenticode"])
        self.assertEqual(r.digest(directory / "install.ps1"), value[0]["sha256"])


if __name__ == "__main__":
    unittest.main()
