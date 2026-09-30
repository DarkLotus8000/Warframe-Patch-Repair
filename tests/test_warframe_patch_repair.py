# From the project root: py -B -m unittest discover -s tests -v
# From this tests directory: py -B -m unittest discover -s . -v
# Or run this file directly: py -B test_warframe_patch_repair.py -v
from __future__ import annotations

import base64
import importlib.util
import io
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "warframe_patch_repair.py"
SPEC = importlib.util.spec_from_file_location("warframe_patch_repair", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {MODULE_PATH}")
repair = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = repair
SPEC.loader.exec_module(repair)

# Python 3.14 re-checks console color capability for unittest's final summary.
# Enable Windows VT processing up front so capturing repair progress does not
# accidentally turn otherwise-green unittest status output white.
if sys.platform == "win32":
    repair._enable_console_colors(sys.stderr)

# Sanitized from the real U44.0.2 B.Cache.Windows_de.bin decoded header.
# The GUID and target hashes are replaced; version, counts, paths and info fields remain real.
U44_V14_DE_MANIFEST_SANITIZED_B64 = (
    "AAAAAAAAAAAAAAAAAAAAAA4AAAABAAAADgAAAC9MYW5ndWFnZXMuYmluAQEBAQEBAQEBAQEBAQEBAW4hUiAcAAAAMQAAAC9M"
    "b3R1cy9JbnRlcmZhY2UvSWNvbnMvTWFya2Vycy9Ob3J0aE1hcmtlcl9lbi5wbmcCAgICAgICAgICAgICAgICugkAYC8AAAAv"
    "TG90dXMvTGFuZ3VhZ2UvVGV4dFNhbml0aXplci9CYW5uZWRXb3Jkc19lbi50cwMDAwMDAwMDAwMDAwMDAwNrEABgMgAAAC9U"
    "ZW1wL0ZvbnRDYWNoZS9FRS9NZW51cy9Gb250cy9Db21tZW50Rm9udC9GX2VuLmZsBAQEBAQEBAQEBAQEBAQEBD4EAGA3AAAA"
    "L1RlbXAvRm9udENhY2hlL0VFL01lbnVzL0ZvbnRzL0NvbW1lbnRGb250L0ZfZW5fc2RmLnBuZwUFBQUFBQUFBQUFBQUFBQUh"
    "dQBgMAAAAC9UZW1wL0ZvbnRDYWNoZS9FRS9NZW51cy9Gb250cy9EZWJ1Z0ZvbnQvRl9lbi5mbAYGBgYGBgYGBgYGBgYGBgbV"
    "AgBgNQAAAC9UZW1wL0ZvbnRDYWNoZS9FRS9NZW51cy9Gb250cy9EZWJ1Z0ZvbnQvRl9lbl9zZGYucG5nBwcHBwcHBwcHBwcH"
    "BwcHB8IgAGA1AAAAL1RlbXAvRm9udENhY2hlL0VFL01lbnVzL0ZvbnRzL0thZWxhRm9udExhcmdlL0ZfZW4uZmwICAgICAgI"
    "CAgICAgICAgI1wMAYDgAAAAvVGVtcC9Gb250Q2FjaGUvRUUvTWVudXMvRm9udHMvS2FlbGFGb250TGFyZ2UvRl9lbl9mLnBu"
    "ZwkJCQkJCQkJCQkJCQkJCQnFSABgOgAAAC9UZW1wL0ZvbnRDYWNoZS9Mb3R1cy9NZW51cy9Gb250cy9BaWxlcm9uc1RpdGxl"
    "U0RGL0ZfZW4uZmwKCgoKCgoKCgoKCgoKCgoK2QUAYD8AAAAvVGVtcC9Gb250Q2FjaGUvTG90dXMvTWVudXMvRm9udHMvQWls"
    "ZXJvbnNUaXRsZVNERi9GX2VuX3NkZi5wbmcLCwsLCwsLCwsLCwsLCwsLE2IAYDwAAAAvVGVtcC9Gb250Q2FjaGUvTG90dXMv"
    "TWVudXMvRm9udHMvRmxhcmVzZXJpZjgyMUJUU0RGL0ZfZW4uZmwMDAwMDAwMDAwMDAwMDAwMHgcAYEEAAAAvVGVtcC9Gb250"
    "Q2FjaGUvTG90dXMvTWVudXMvRm9udHMvRmxhcmVzZXJpZjgyMUJUU0RGL0ZfZW5fc2RmLnBuZw0NDQ0NDQ0NDQ0NDQ0NDQ1T"
    "WQBgNgAAAC9UZW1wL0ZvbnRDYWNoZS9Mb3R1cy9NZW51cy9Gb250cy9JbWJ1ZUJvbGRTREYvRl9lbi5mbA4ODg4ODg4ODg4O"
    "Dg4ODg6cBwBgOwAAAC9UZW1wL0ZvbnRDYWNoZS9Mb3R1cy9NZW51cy9Gb250cy9JbWJ1ZUJvbGRTREYvRl9lbl9zZGYucG5n"
    "Dw8PDw8PDw8PDw8PDw8PDzdSAWA5AAAAL1RlbXAvRm9udENhY2hlL0xvdHVzL01lbnVzL0ZvbnRzL0ltYnVlUmVndWxhclNE"
    "Ri9GX2VuLmZsEBAQEBAQEBAQEBAQEBAQEHYHAGA+AAAAL1RlbXAvRm9udENhY2hlL0xvdHVzL01lbnVzL0ZvbnRzL0ltYnVl"
    "UmVndWxhclNERi9GX2VuX3NkZi5wbmcRERERERERERERERERERERB80AYDsAAAAvVGVtcC9Gb250Q2FjaGUvTG90dXMvTWVu"
    "dXMvRm9udHMvTm90b1NhbnNGaXhlZFNpemUvRl9lbi5mbBISEhISEhISEhISEhISEhJ7DQBgPgAAAC9UZW1wL0ZvbnRDYWNo"
    "ZS9Mb3R1cy9NZW51cy9Gb250cy9Ob3RvU2Fuc0ZpeGVkU2l6ZS9GX2VuX2YucG5nExMTExMTExMTExMTExMTE0VVAGA/AAAA"
    "L1RlbXAvRm9udENhY2hlL0xvdHVzL01lbnVzL0ZvbnRzL05vdG9TYW5zSW5wdXRGaWVsZFNERi9GX2VuLmZsFBQUFBQUFBQU"
    "FBQUFBQUFCYRAGBEAAAAL1RlbXAvRm9udENhY2hlL0xvdHVzL01lbnVzL0ZvbnRzL05vdG9TYW5zSW5wdXRGaWVsZFNERi9G"
    "X2VuX3NkZi5wbmcVFRUVFRUVFRUVFRUVFRUVzH4BYDcAAAAvVGVtcC9Gb250Q2FjaGUvTG90dXMvTWVudXMvRm9udHMvUm9i"
    "b3RvQm9sZFNERi9GX2VuLmZsFhYWFhYWFhYWFhYWFhYWFv8GAGA8AAAAL1RlbXAvRm9udENhY2hlL0xvdHVzL01lbnVzL0Zv"
    "bnRzL1JvYm90b0JvbGRTREYvRl9lbl9zZGYucG5nFxcXFxcXFxcXFxcXFxcXF+S0AGBCAAAAL1RlbXAvRm9udENhY2hlL0xv"
    "dHVzL01lbnVzL0ZvbnRzL1JvYm90b0NvbmRlbnNlZEl0YWxpY1NERi9GX2VuLmZsGBgYGBgYGBgYGBgYGBgYGAoIAGBHAAAA"
    "L1RlbXAvRm9udENhY2hlL0xvdHVzL01lbnVzL0ZvbnRzL1JvYm90b0NvbmRlbnNlZEl0YWxpY1NERi9GX2VuX3NkZi5wbmcZ"
    "GRkZGRkZGRkZGRkZGRkZErYAYDwAAAAvVGVtcC9Gb250Q2FjaGUvTG90dXMvTWVudXMvRm9udHMvUm9ib3RvQ29uZGVuc2Vk"
    "U0RGL0ZfZW4uZmwaGhoaGhoaGhoaGhoaGhoa/gYAYEEAAAAvVGVtcC9Gb250Q2FjaGUvTG90dXMvTWVudXMvRm9udHMvUm9i"
    "b3RvQ29uZGVuc2VkU0RGL0ZfZW5fc2RmLnBuZxsbGxsbGxsbGxsbGxsbGxu9pwBgOgAAAC9UZW1wL0ZvbnRDYWNoZS9Mb3R1"
    "cy9NZW51cy9Gb250cy9Sb2JvdG9SZWd1bGFyU0RGL0ZfZW4uZmwcHBwcHBwcHBwcHBwcHBwc9QYAYD8AAAAvVGVtcC9Gb250"
    "Q2FjaGUvTG90dXMvTWVudXMvRm9udHMvUm9ib3RvUmVndWxhclNERi9GX2VuX3NkZi5wbmcdHR0dHR0dHR0dHR0dHR0d57AA"
    "YAAAAAA="
)

def packages_header(version: int) -> bytes:
    data = bytearray(28)
    struct.pack_into("<I", data, 16, 20)
    struct.pack_into("<I", data, 20, version)
    struct.pack_into("<I", data, 24, 1)
    return bytes(data)

def empty_manifest(version: int) -> bytes:
    data = bytearray(32)
    struct.pack_into("<I", data, 16, version)
    return bytes(data)

class PackagesSelectionTests(unittest.TestCase):
    def _make_object(self, content_root: Path, type_id: int, digest: bytes, payload: bytes) -> Path:
        directory = content_root / "0"
        directory.mkdir(parents=True, exist_ok=True)
        name = f"Packages.bin!{type_id:X}_{repair.b64m_encode(digest)}"
        path = directory / name
        path.write_bytes(payload)
        return path

    def test_ambiguity_is_decided_before_packages_version_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            digest_v46 = bytes(range(16))
            digest_v47 = bytes(range(16, 32))
            self._make_object(content_root, 0x10, digest_v46, b"v46")
            self._make_object(content_root, 0x11, digest_v47, b"v47")

            def fake_shcc(data: bytes, _oodle):
                if data == b"v46":
                    return packages_header(46), digest_v46
                if data == b"v47":
                    return packages_header(47), digest_v47
                raise AssertionError("unexpected fixture")

            with patch.object(repair, "shcc_header_and_hash", side_effect=fake_shcc), patch.object(
                repair,
                "_read_packages_parent_index",
                side_effect=AssertionError("format parser must not run before ambiguity check"),
            ):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(repair.PackagesAmbiguityError):
                        repair._load_packages_parent_index(content_root, object())

    def test_single_unsupported_packages_version_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            digest = bytes(range(16))
            self._make_object(content_root, 0x10, digest, b"v47")

            with patch.object(
                repair,
                "shcc_header_and_hash",
                return_value=(packages_header(47), digest),
            ):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(repair.UnsupportedPackagesVersionError):
                        repair._load_packages_parent_index(content_root, object())

    def test_single_integrity_valid_unreadable_layout_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            digest = bytes(range(16))
            self._make_object(content_root, 0x10, digest, b"changed-v46")

            with patch.object(
                repair,
                "shcc_header_and_hash",
                return_value=(packages_header(46), digest),
            ), patch.object(
                repair,
                "_read_packages_parent_index",
                side_effect=repair.RepairError("directory-block structure changed"),
            ):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(repair.UnsupportedPackagesLayoutError):
                        repair._load_packages_parent_index(content_root, object())

    def test_single_integrity_valid_v46_object_reaches_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            digest = bytes(range(16))
            path = self._make_object(content_root, 0x2A, digest, b"v46")
            expected = repair.PackagesParentIndex(
                version=46,
                entity_count=3,
                parents={"/Lotus/A": "/Lotus/B"},
                layout="v46 directory-block",
                directory_blocks=1,
            )

            with patch.object(
                repair,
                "shcc_header_and_hash",
                return_value=(packages_header(46), digest),
            ), patch.object(repair, "_read_packages_parent_index", return_value=expected) as parser:
                with redirect_stdout(io.StringIO()):
                    selected_path, type_id, index = repair._load_packages_parent_index(
                        content_root, object()
                    )

            self.assertEqual(selected_path, path)
            self.assertEqual(type_id, 0x2A)
            self.assertIs(index, expected)
            parser.assert_called_once_with(packages_header(46))

class OptionalExeExtractionTests(unittest.TestCase):
    def test_unexpected_extractor_exception_is_normalized(self) -> None:
        class BrokenExtractor:
            def __init__(self, _path: Path):
                pass

            def extract(self):
                raise IndexError("new executable pattern")

        exe = Path("Warframe.x64.exe")
        with patch.object(repair, "_WarframeTypeExtractor", BrokenExtractor):
            with self.assertRaises(repair.RepairError) as caught:
                repair.extract_type_tables_from_exe(exe)

        self.assertIn("Unexpected Warframe executable analysis failure", str(caught.exception))
        self.assertIn("new executable pattern", str(caught.exception))

    def test_existing_repair_error_is_preserved(self) -> None:
        class ExpectedFailureExtractor:
            def __init__(self, _path: Path):
                raise repair.RepairError("known extractor failure")

        with patch.object(repair, "_WarframeTypeExtractor", ExpectedFailureExtractor):
            with self.assertRaisesRegex(repair.RepairError, "known extractor failure"):
                repair.extract_type_tables_from_exe(Path("Warframe.x64.exe"))

class ManifestHeaderTests(unittest.TestCase):
    def test_supported_manifest_version_parses(self) -> None:
        header = empty_manifest(repair.SUPPORTED_MANIFEST_VERSION)
        with patch.object(
            repair,
            "_manifest_header_version",
            wraps=repair._manifest_header_version,
        ) as version_reader:
            self.assertEqual(list(repair.parse_manifest_header(header)), [])
        version_reader.assert_called_once_with(header)

    def test_unsupported_manifest_version_is_fatal(self) -> None:
        with self.assertRaises(repair.UnsupportedManifestVersionError):
            list(repair.parse_manifest_header(empty_manifest(15)))

    def test_manifest_parser_rejects_truncated_header(self) -> None:
        with self.assertRaises(repair.RepairError):
            list(repair.parse_manifest_header(b"\x00" * 19))

    def test_manifest_parser_requires_exact_payload_consumption(self) -> None:
        header = empty_manifest(repair.SUPPORTED_MANIFEST_VERSION) + b"\x00"
        with self.assertRaisesRegex(repair.RepairError, "Unexpected 1 trailing byte"):
            list(repair.parse_manifest_header(header))

    def test_collect_manifest_assets_propagates_unsupported_version(self) -> None:
        class DummyOodle:
            pass

        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            digest = bytes(range(16))
            directory = content_root / "0"
            directory.mkdir()
            name = f"B.Cache.Windows.bin!1_{repair.b64m_encode(digest)}"
            (directory / name).write_bytes(b"fixture")
            manifests = repair.manifest_files(content_root)
            with patch.object(
                repair,
                "shcc_header_and_hash",
                return_value=(empty_manifest(15), digest),
            ), redirect_stdout(io.StringIO()):
                with self.assertRaises(repair.UnsupportedManifestVersionError):
                    repair.collect_manifest_assets(manifests, DummyOodle())

    def test_u44_v14_sanitized_real_manifest_fixture(self) -> None:
        header = base64.b64decode(U44_V14_DE_MANIFEST_SANITIZED_B64)
        rows = list(repair.parse_manifest_header(header))

        self.assertEqual(repair._manifest_header_version(header), 14)
        self.assertEqual(len(rows), 29)
        self.assertEqual(sum(section == "service" for section, _, _ in rows), 1)
        self.assertEqual(sum(section == "packed" for section, _, _ in rows), 28)
        self.assertEqual(sum(section == "stripped" for section, _, _ in rows), 0)
        self.assertEqual(rows[0][0:2], ("service", "/Languages.bin"))
        self.assertIn(
            "/Lotus/Interface/Icons/Markers/NorthMarker_en.png",
            {path for _, path, _ in rows},
        )

    def test_u44_language_manifest_owner_controls_namespace_and_summary_version(self) -> None:
        header = base64.b64decode(U44_V14_DE_MANIFEST_SANITIZED_B64)
        digest = bytes(range(16))

        for suffix in ("de", "xx"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temp:
                name = f"B.Cache.Windows_{suffix}.bin!E_{repair.b64m_encode(digest)}"
                path = Path(temp) / name
                path.write_bytes(b"fixture")
                match = repair.MANIFEST_RE.fullmatch(name)
                self.assertIsNotNone(match)
                output = io.StringIO()

                with patch.object(
                    repair,
                    "shcc_header_and_hash",
                    return_value=(header, digest),
                ), redirect_stdout(output):
                    assets, failures = repair.collect_manifest_assets([(path, match)], object())

                self.assertEqual(failures, 0)
                self.assertEqual(len(assets), 29)
                self.assertTrue(all(asset.namespace == f"0_{suffix}" for asset in assets))
                north_marker = next(
                    asset
                    for asset in assets
                    if asset.logical_path.endswith("/NorthMarker_en.png")
                )
                self.assertEqual(north_marker.namespace, f"0_{suffix}")
                self.assertIn(
                    "[Manifest] v14 | Sections: service: 1 | packed: 28 | stripped: 0",
                    output.getvalue(),
                )

    def test_collect_manifest_assets_keeps_truncated_header_as_per_manifest_failure(self) -> None:
        digest = bytes(range(16))
        name = f"B.Cache.Windows.bin!E_{repair.b64m_encode(digest)}"
        match = repair.MANIFEST_RE.fullmatch(name)
        self.assertIsNotNone(match)

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / name
            path.write_bytes(b"fixture")
            with patch.object(
                repair,
                "shcc_header_and_hash",
                return_value=(b"\x00" * 16, digest),
            ), patch.object(repair, "print_error") as error_printer, redirect_stdout(io.StringIO()):
                assets, failures = repair.collect_manifest_assets([(path, match)], object())

        self.assertEqual(assets, [])
        self.assertEqual(failures, 1)
        error_printer.assert_called_once()
        self.assertIn("Could not parse cache manifest", error_printer.call_args.args[0])

    def test_manifest_filename_grammar_accepts_only_supported_family_shapes(self) -> None:
        digest = repair.b64m_encode(bytes(range(16)))
        valid = (
            f"B.Cache.Windows.bin!E_{digest}",
            f"B.Cache.Windows_de.bin!E_{digest}",
            f"B.Cache.Windows_xx.bin!E_{digest}",
            f"B.Cache.Windows_en2.bin!E_{digest}",
            f"B.Cache.Dx11.bin!E_{digest}",
            f"B.Cache.Dx12.bin!E_{digest}",
        )
        invalid = (
            f"B.Cache.Windowsfoo.bin!E_{digest}",
            f"B.Cache.Windows_.bin!E_{digest}",
            f"B.Cache.Windows__xx.bin!E_{digest}",
            f"B.Cache.Windows_ä.bin!E_{digest}",
            f"B.Cache.Dx11_de.bin!E_{digest}",
            f"B.Cache.Dx12_xx.bin!E_{digest}",
        )

        for name in valid:
            with self.subTest(name=name):
                self.assertIsNotNone(repair.MANIFEST_RE.fullmatch(name))
        for name in invalid:
            with self.subTest(name=name):
                self.assertIsNone(repair.MANIFEST_RE.fullmatch(name))

    def test_duplicate_same_family_target_manifests_are_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            directory = content_root / "0"
            directory.mkdir()
            first_hash = repair.b64m_encode(bytes(range(16)))
            second_hash = repair.b64m_encode(bytes(range(16, 32)))
            (directory / f"B.Cache.Windows_de.bin!E_{first_hash}").write_bytes(b"first")
            (directory / f"B.Cache.Windows_de.bin!E_{second_hash}").write_bytes(b"second")

            with self.assertRaisesRegex(
                repair.RepairError,
                "Multiple target manifests were found for the same cache family",
            ):
                repair.manifest_files(content_root)

class ShccOodleTests(unittest.TestCase):
    @staticmethod
    def _direct_shcc(header: bytes) -> bytes:
        chunk = bytes((0,)) + struct.pack("<II", len(header), len(header)) + header
        body = repair.SHCC_PREAMBLE + chunk + b"\x52"
        return body + struct.pack("<I", repair.crc32c(body))

    def test_direct_shcc_valid_crc_and_hash(self) -> None:
        digest = bytes(range(16))
        data = self._direct_shcc(digest)

        header, actual_digest = repair.shcc_header_and_hash(data, object())
        self.assertEqual(header, digest)
        self.assertEqual(actual_digest, digest)
        repair.validate_shcc(data, repair.b64m_encode(digest), object())

    def test_direct_shcc_corrupted_crc_is_rejected(self) -> None:
        data = bytearray(self._direct_shcc(bytes(range(16))))
        data[-1] ^= 0x01

        with self.assertRaisesRegex(repair.RepairError, "SHCC CRC32C mismatch"):
            repair.shcc_header_and_hash(data, object())

    def test_direct_shcc_wrong_expected_hash_is_rejected(self) -> None:
        digest = bytes(range(16))
        data = self._direct_shcc(digest)
        wrong = repair.b64m_encode(bytes(range(16, 32)))

        with self.assertRaisesRegex(repair.RepairError, "SHCC hash mismatch"):
            repair.validate_shcc(data, wrong, object())

    @staticmethod
    def _outer_wrapped_shcc(header: bytes):
        inner = repair.SHCC_PREAMBLE + bytes((0,)) + struct.pack(
            "<II", len(header), len(header)
        ) + header
        compressed = b"synthetic-outer-wrapper"
        body = compressed + struct.pack("<I", len(inner)) + b"\x43"
        wrapped = body + struct.pack("<I", repair.crc32c(body))

        class FakeOodle:
            def decompress(self, block: bytes, expected_size: int) -> bytes:
                if bytes(block) != compressed:
                    raise AssertionError("unexpected outer-wrapper payload")
                if expected_size != len(inner):
                    raise AssertionError("unexpected outer-wrapper raw size")
                return inner

        return wrapped, FakeOodle()

    def test_outer_43_shcc_valid_crc_and_hash(self) -> None:
        digest = bytes(range(16))
        data, oodle = self._outer_wrapped_shcc(digest)

        repair.validate_shcc(data, repair.b64m_encode(digest), oodle)

    def test_outer_43_shcc_corrupted_crc_is_rejected(self) -> None:
        data, oodle = self._outer_wrapped_shcc(bytes(range(16)))
        corrupted = bytearray(data)
        corrupted[-1] ^= 0x01

        with self.assertRaisesRegex(repair.RepairError, "Outer SHCC CRC32C mismatch"):
            repair.validate_shcc(corrupted, repair.b64m_encode(bytes(range(16))), oodle)

    def test_oodle_payload_rejects_trailing_bytes(self) -> None:
        class FakeOodle:
            def decompress(self, block: bytes, expected_size: int) -> bytes:
                self_block = bytes(block)
                if not self_block.startswith(b"\x8C"):
                    raise AssertionError("unexpected synthetic Oodle block")
                return b"A" * expected_size

        block = b"\x8Csynthetic"
        decompressed_size = 4
        num1 = 0x80000000 | (len(block) << 2)
        num2 = (decompressed_size << 5) | 1
        block_info = num1.to_bytes(4, "big") + num2.to_bytes(4, "big")
        payload = block_info + block + b"extra"

        with self.assertRaisesRegex(
            repair.RepairError,
            "Unexpected 5 trailing bytes in Oodle chunk payload",
        ):
            repair._decompress_oodle_payload(payload, decompressed_size, FakeOodle())

class FilesystemDiagnosticTests(unittest.TestCase):
    def test_packages_enumeration_error_is_not_reported_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            (content_root / "0").mkdir()
            with patch.object(Path, "iterdir", side_effect=OSError("access denied")):
                with self.assertRaisesRegex(repair.RepairError, "Could not enumerate captured Packages"):
                    repair._find_packages_objects(content_root)

    def test_cache_windows_enumeration_error_is_not_reported_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target_root = Path(temp)
            with patch.object(Path, "iterdir", side_effect=OSError("access denied")):
                with self.assertRaisesRegex(repair.RepairError, "while locating Cache.Windows"):
                    repair.find_cache_windows_dir(target_root)

if __name__ == "__main__":
    unittest.main()
