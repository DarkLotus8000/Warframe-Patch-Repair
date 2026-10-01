# From the project root: py -B -m unittest discover -s tests -v
# From this tests directory: py -B -m unittest discover -s . -v
# Or run this file directly: py -B test_warframe_patch_repair.py -v
from __future__ import annotations

import base64
import importlib.util
import io
import struct
import sys
import threading
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
# The embedded object hash and target hashes are replaced; version, counts, paths and info fields remain real.
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

def single_service_manifest(path: str, digest: bytes, info: int) -> bytes:
    raw_path = path.encode("utf-8")
    data = bytearray(20)
    struct.pack_into("<I", data, 16, repair.SUPPORTED_MANIFEST_VERSION)
    data.extend(struct.pack("<I", 1))
    data.extend(struct.pack("<I", len(raw_path)))
    data.extend(raw_path)
    data.extend(digest)
    data.extend(struct.pack("<I", info))
    data.extend(struct.pack("<I", 0))
    data.extend(struct.pack("<I", 0))
    return bytes(data)

class FakeCurlError(Exception):
    pass

class FakePycurl:
    URL = 1
    HTTPGET = 2
    USERAGENT = 3
    HTTPHEADER = 4
    FOLLOWLOCATION = 5
    MAXREDIRS = 6
    CONNECTTIMEOUT = 7
    LOW_SPEED_LIMIT = 8
    LOW_SPEED_TIME = 9
    NOSIGNAL = 10
    SSL_VERIFYPEER = 11
    SSL_VERIFYHOST = 12
    HEADERFUNCTION = 13
    WRITEFUNCTION = 14
    RESPONSE_CODE = 15
    error = FakeCurlError

    def __init__(self, responses):
        self.responses = iter(responses)
        self.created = 0
        self.handles = []

    def Curl(self):
        self.created += 1
        handle = FakeCurl(self)
        self.handles.append(handle)
        return handle

class FakeCurl:
    def __init__(self, module):
        self.module = module
        self.options = {}
        self.history = []
        self.status = 0

    def reset(self):
        self.options = {}

    def setopt(self, option, value):
        self.options[option] = value

    def perform(self):
        response = next(self.module.responses)
        transfers = response if isinstance(response, list) else [response]
        self.history.append(dict(self.options))
        header_callback = self.options[self.module.HEADERFUNCTION]
        write_callback = self.options[self.module.WRITEFUNCTION]

        for transfer in transfers:
            self.status = int(transfer.get("status", 200))
            reason = transfer.get("reason", "OK")
            header_lines = [f"HTTP/1.1 {self.status} {reason}\r\n".encode("ascii")]
            content_length = transfer.get("content_length")
            if content_length is not None:
                header_lines.append(f"Content-Length: {content_length}\r\n".encode("ascii"))
            header_lines.append(b"\r\n")
            for line in header_lines:
                if header_callback(line) != len(line):
                    raise FakeCurlError(23, "Failure writing header")
            for chunk in transfer.get("chunks", []):
                if write_callback(chunk) != len(chunk):
                    raise FakeCurlError(23, "Failure writing body")

    def getinfo(self, option):
        if option == self.module.RESPONSE_CODE:
            return self.status
        raise AssertionError(f"unexpected getinfo option {option}")

class FakeTTY(io.StringIO):
    def isatty(self):
        return True

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

class TypeEvidenceTests(unittest.TestCase):
    @staticmethod
    def _observation(namespace: str, type_id: int) -> repair.ObservedObject:
        return repair.ObservedObject(
            namespace=namespace,
            logical_path="/Languages.bin",
            type_id=type_id,
            expected_hash=f"hash-{namespace}-{type_id}",
            path=Path(namespace) / "Languages.bin",
        )

    def test_same_path_namespace_group_evidence_resolves_language_root_asset(self) -> None:
        observations = [
            self._observation("0_en", 0x44),
            self._observation("0_de", 0x44),
        ]
        with redirect_stdout(io.StringIO()):
            evidence = repair.build_patch_type_evidence(observations, None, None)
        resolver = repair.TypeResolver(None, None, evidence)

        self.assertEqual(
            resolver.resolve_patch("0_ja", "/Languages.bin"),
            (0x44, "patch-local same-path namespace-group evidence"),
        )

        conflicting = [
            self._observation("0_en", 0x44),
            self._observation("0_de", 0x45),
        ]
        with redirect_stdout(io.StringIO()):
            conflicting_evidence = repair.build_patch_type_evidence(conflicting, None, None)
        conflicting_resolver = repair.TypeResolver(None, None, conflicting_evidence)
        self.assertEqual(
            conflicting_resolver.resolve_patch("0_ja", "/Languages.bin"),
            (None, None),
        )

    def test_base_namespace_group_hint_repairs_missing_language_root_asset(self) -> None:
        hints = {
            ("0_en", "/Languages.bin"): 0x44,
            ("0_de", "/Languages.bin"): 0x44,
        }
        grouped = repair._group_namespace_type_hints(hints)
        self.assertEqual(grouped[("0", "/Languages.bin")], 0x44)
        self.assertNotIn(
            ("0", "/Languages.bin"),
            repair._group_namespace_type_hints(
                {
                    ("0_en", "/Languages.bin"): 0x44,
                    ("0_de", "/Languages.bin"): 0x45,
                }
            ),
        )

        asset = repair.ManifestAsset(
            namespace="0_ja",
            section="service",
            logical_path="/Languages.bin",
            manifest_hash=bytes(range(16)),
            info=0,
        )
        resolver = repair.TypeResolver(None, None, None)
        with tempfile.TemporaryDirectory() as temp, patch.object(
            repair,
            "repair_object",
            return_value=("downloaded", "CDN", 200),
        ) as downloader:
            content_root = Path(temp)
            status, detail, name, http_status = repair.repair_manifest_asset(
                asset,
                content_root=content_root,
                source_content_root=content_root,
                oodle=object(),
                resolver=resolver,
                label="Completion",
                base_group_type_hint=grouped[("0", "/Languages.bin")],
            )

        expected_name = repair.cache_name(
            "/Languages.bin", 0x44, asset.hash_b64, "0_ja"
        )
        self.assertEqual((status, name, http_status), ("downloaded", expected_name, 200))
        self.assertIn("namespace-group CommonHeader type hint", detail or "")
        downloader.assert_called_once()
        self.assertEqual(downloader.call_args.kwargs["content_root"], content_root)
        self.assertEqual(downloader.call_args.kwargs["name"], expected_name)
        self.assertEqual(downloader.call_args.kwargs["expected_hash"], asset.hash_b64)
        self.assertEqual(downloader.call_args.kwargs["label"], "Completion")

    def test_dx_namespace_type_evidence_stays_isolated(self) -> None:
        path = "/Lotus/Shader/Example.bin"
        observations = [
            repair.ObservedObject(
                namespace="9",
                logical_path=path,
                type_id=0x91,
                expected_hash="dx11",
                path=Path("9") / "Example.bin",
            ),
            repair.ObservedObject(
                namespace="A",
                logical_path=path,
                type_id=0xA1,
                expected_hash="dx12",
                path=Path("A") / "Example.bin",
            ),
        ]
        with redirect_stdout(io.StringIO()):
            evidence = repair.build_patch_type_evidence(observations, None, None)
        resolver = repair.TypeResolver(None, None, evidence)

        self.assertEqual(resolver.resolve_patch("9", path)[0], 0x91)
        self.assertEqual(resolver.resolve_patch("A", path)[0], 0xA1)
        self.assertEqual(repair._namespace_group("9"), "9")
        self.assertEqual(repair._namespace_group("A"), "A")

    def test_base_package_namespace_maps_dx_variants(self) -> None:
        self.assertEqual(repair._cache_namespace_from_package("H.ShaderDx11"), "9")
        self.assertEqual(
            repair._cache_namespace_from_package("H.ShaderPermutationDx12"), "A"
        )
        self.assertEqual(repair._cache_namespace_from_package("H.Misc_en"), "0_en")

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
        self.assertEqual(sum(section == "service" for section, _, _, _ in rows), 1)
        self.assertEqual(sum(section == "packed" for section, _, _, _ in rows), 28)
        self.assertEqual(sum(section == "stripped" for section, _, _, _ in rows), 0)
        self.assertEqual(rows[0][0:2], ("service", "/Languages.bin"))
        self.assertEqual(rows[0][3], 0x2052216E)
        self.assertIn(
            "/Lotus/Interface/Icons/Markers/NorthMarker_en.png",
            {path for _, path, _, _ in rows},
        )

    def test_manifest_info_uses_28_bit_cdn_size(self) -> None:
        asset = repair.ManifestAsset(
            namespace="0",
            section="service",
            logical_path="/Packages.bin",
            manifest_hash=bytes(range(16)),
            info=0x2150EF7E,
        )
        self.assertEqual(asset.cdn_size, 22_081_406)
        self.assertEqual(asset.cache_flags, 0x2)
        self.assertGreater(asset.cdn_size, 0xFFFFFF)

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

    def test_voiceover_filename_remains_in_owning_language_namespace(self) -> None:
        digest = bytes(range(16))
        target_hash = bytes(range(16, 32))
        logical_path = "/Lotus/Sounds/Dialog/SyntheticLine_en.wav"
        header = single_service_manifest(logical_path, target_hash, 0x60012345)
        name = f"B.Cache.Windows_zh.bin!E_{repair.b64m_encode(digest)}"
        match = repair.MANIFEST_RE.fullmatch(name)
        self.assertIsNotNone(match)

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / name
            path.write_bytes(b"fixture")
            with patch.object(
                repair,
                "shcc_header_and_hash",
                return_value=(header, digest),
            ), redirect_stdout(io.StringIO()):
                assets, failures = repair.collect_manifest_assets([(path, match)], object())

        self.assertEqual(failures, 0)
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].logical_path, logical_path)
        self.assertEqual(assets[0].namespace, "0_zh")

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

class HCacheCompletionTests(unittest.TestCase):
    @staticmethod
    def _header(entries: list[tuple[str, bytes]], version: int = 13) -> bytes:
        data = bytearray(20)
        struct.pack_into("<I", data, 16, version)
        # Real H.Cache manifests include an empty leading group before the
        # populated path/hash group.
        data.extend(struct.pack("<I", 0))
        data.extend(struct.pack("<I", len(entries)))
        for logical_path, target_hash in entries:
            raw_path = logical_path.encode("utf-8")
            data.extend(struct.pack("<I", len(raw_path)))
            data.extend(raw_path)
            data.extend(target_hash)
            data.extend(b"\x00\x00\x00\x00")
        return bytes(data)

    @staticmethod
    def _manifest(name: str):
        match = repair.MANIFEST_RE.fullmatch(name)
        if match is None:
            raise AssertionError(f"invalid test manifest name: {name}")
        return Path(name), match

    @classmethod
    def _h_cache_object(cls, entries: list[tuple[str, bytes]], version: int = 13) -> bytes:
        header = bytearray(cls._header(entries, version=version))
        embedded = repair.hashlib.md5(repair.SHCC_PREAMBLE + header[16:]).digest()
        header[:16] = embedded
        chunk = bytes((0,)) + struct.pack("<II", len(header), len(header)) + bytes(header)
        body = repair.SHCC_PREAMBLE + chunk + b"\x52"
        return body + struct.pack("<I", repair.crc32c(body))

    def test_h_cache_origin_url_uses_manifest_type_and_sentinel_hash(self) -> None:
        self.assertEqual(
            repair._h_cache_origin_url(0xE),
            "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w",
        )

    def test_h_cache_parser_exposes_supported_b_cache_families(self) -> None:
        windows = bytes(range(16))
        german = bytes(range(16, 32))
        other = bytes(range(32, 48))
        index = repair.parse_h_cache_header(
            self._header(
                [
                    ("/B.Cache.Windows.bin", windows),
                    ("/B.Cache.Windows_de.bin", german),
                    ("/Unrelated.bin", other),
                ]
            )
        )

        self.assertEqual(index.version, 13)
        self.assertEqual(index.entries["/B.Cache.Windows.bin"], windows)
        families = repair._h_cache_b_cache_entries(index)
        self.assertEqual(len(families), 2)
        self.assertEqual(families[("Windows", None)], ("/B.Cache.Windows.bin", windows))
        self.assertEqual(families[("Windows", "_de")], ("/B.Cache.Windows_de.bin", german))

    def test_h_cache_rejects_unknown_b_cache_family(self) -> None:
        index = repair.HCacheIndex(
            version=13,
            entries={"/B.Cache.Vulkan.bin": bytes(range(16))},
        )
        with self.assertRaisesRegex(repair.RepairError, "Unsupported B.Cache family"):
            repair._h_cache_b_cache_entries(index)

    def test_h_cache_target_match_requires_every_captured_manifest_hash(self) -> None:
        spanish = bytes(range(16))
        german = bytes(range(16, 32))
        spanish_name = f"B.Cache.Windows_es.bin!E_{repair.b64m_encode(spanish)}"
        manifests = [self._manifest(spanish_name)]
        matching = repair.HCacheIndex(
            version=13,
            entries={
                "/B.Cache.Windows_es.bin": spanish,
                "/B.Cache.Windows_de.bin": german,
            },
        )

        matches, reason, count = repair._h_cache_matches_captured(matching, manifests)
        self.assertTrue(matches)
        self.assertEqual(reason, "")
        self.assertEqual(count, 1)

        mismatched = repair.HCacheIndex(
            version=13,
            entries={"/B.Cache.Windows_es.bin": german},
        )
        matches, reason, count = repair._h_cache_matches_captured(mismatched, manifests)
        self.assertFalse(matches)
        self.assertEqual(count, 0)
        self.assertIn("hash differs", reason)

    def test_h_cache_object_requires_valid_embedded_self_hash(self) -> None:
        header = bytearray(self._header([("/B.Cache.Windows.bin", bytes(range(16)))]))
        embedded = repair.hashlib.md5(repair.SHCC_PREAMBLE + header[16:]).digest()
        header[:16] = embedded
        chunk = bytes((0,)) + struct.pack("<II", len(header), len(header)) + bytes(header)
        body = repair.SHCC_PREAMBLE + chunk + b"\x52"
        data = body + struct.pack("<I", repair.crc32c(body))

        index = repair._decode_h_cache_object(data, object(), progress_name="H.Cache")
        self.assertEqual(index.version, 13)

        corrupted_header = bytearray(header)
        corrupted_header[-1] ^= 0x01
        chunk = bytes((0,)) + struct.pack(
            "<II", len(corrupted_header), len(corrupted_header)
        ) + bytes(corrupted_header)
        body = repair.SHCC_PREAMBLE + chunk + b"\x52"
        corrupted = body + struct.pack("<I", repair.crc32c(body))
        with self.assertRaisesRegex(repair.RepairError, "embedded object hash"):
            repair._decode_h_cache_object(corrupted, object(), progress_name="H.Cache")

    def test_h_cache_completion_recovers_missing_manifest_objects(self) -> None:
        spanish = bytes(range(16))
        german = bytes(range(16, 32))
        dx11 = bytes(range(32, 48))
        dx12 = bytes(range(48, 64))
        index = repair.HCacheIndex(
            version=13,
            entries={
                "/B.Cache.Windows_es.bin": spanish,
                "/B.Cache.Windows_de.bin": german,
                "/B.Cache.Dx11.bin": dx11,
                "/B.Cache.Dx12.bin": dx12,
            },
        )

        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            directory = content_root / "0"
            directory.mkdir()
            spanish_name = f"B.Cache.Windows_es.bin!E_{repair.b64m_encode(spanish)}"
            (directory / spanish_name).write_bytes(b"existing")
            manifests = repair.manifest_files(content_root)
            recovered_names: list[str] = []

            def fake_repair_object(**kwargs):
                name = kwargs["name"]
                recovered_names.append(name)
                destination = repair.local_path(content_root, name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"recovered")
                return "downloaded", "CDN", 200

            with patch.object(
                repair,
                "_matching_h_cache_index",
                return_value=(index, 0xE),
            ), patch.object(
                repair,
                "repair_object",
                side_effect=fake_repair_object,
            ), redirect_stdout(io.StringIO()):
                completed = repair.complete_target_manifests_from_h_cache(
                    content_root,
                    manifests,
                    object(),
                )

        self.assertEqual(completed.state, "verified-recovered")
        self.assertEqual(completed.recovered, 3)
        self.assertEqual(len(completed.manifests), 4)
        self.assertEqual(
            recovered_names,
            [
                f"0/B.Cache.Dx11.bin!E_{repair.b64m_encode(dx11)}",
                f"0/B.Cache.Dx12.bin!E_{repair.b64m_encode(dx12)}",
                f"0/B.Cache.Windows_de.bin!E_{repair.b64m_encode(german)}",
            ],
        )

    def test_h_cache_completion_reports_unverified_when_target_cannot_be_proven(self) -> None:
        digest = bytes(range(16))
        manifests = [self._manifest(f"B.Cache.Windows_es.bin!E_{repair.b64m_encode(digest)}")]

        with patch.object(repair, "_matching_h_cache_index", return_value=None), redirect_stdout(io.StringIO()):
            result = repair.complete_target_manifests_from_h_cache(Path("."), manifests, object())

        self.assertEqual(result.state, "unverified")
        self.assertFalse(result.verified)
        self.assertFalse(repair.ManifestCoverageResult([], "unexpected-state").verified)
        self.assertEqual(result.manifests, manifests)

    def test_captured_h_cache_bootstraps_when_no_b_cache_was_captured(self) -> None:
        windows = bytes(range(16))
        german = bytes(range(16, 32))
        h_cache = self._h_cache_object(
            [
                ("/B.Cache.Windows.bin", windows),
                ("/B.Cache.Windows_de.bin", german),
            ]
        )

        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            directory = content_root / "0"
            directory.mkdir()
            h_name = repair._h_cache_filename(0xE)
            (directory / h_name).write_bytes(h_cache)
            recovered_names: list[str] = []

            def fake_repair_object(**kwargs):
                name = kwargs["name"]
                recovered_names.append(name)
                destination = repair.local_path(content_root, name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"recovered")
                return "downloaded", "CDN", 200

            with patch.object(repair, "repair_object", side_effect=fake_repair_object), redirect_stdout(io.StringIO()):
                result = repair.complete_target_manifests_from_h_cache(
                    content_root,
                    [],
                    object(),
                )

        self.assertEqual(result.state, "verified-recovered")
        self.assertEqual(result.recovered, 2)
        self.assertEqual(len(result.manifests), 2)
        self.assertEqual(
            recovered_names,
            [
                f"0/B.Cache.Windows.bin!E_{repair.b64m_encode(windows)}",
                f"0/B.Cache.Windows_de.bin!E_{repair.b64m_encode(german)}",
            ],
        )

    def test_content_root_can_be_resolved_from_captured_h_cache_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target_root = Path(temp)
            content_root = target_root / "OpenWF" / "Content"
            directory = content_root / "0"
            directory.mkdir(parents=True)
            (directory / repair._h_cache_filename(0xE)).write_bytes(b"captured")

            self.assertEqual(repair.resolve_content_root(target_root), content_root)

    def test_content_root_prefers_b_cache_evidence_over_earlier_h_cache_only_root(self) -> None:
        digest = repair.b64m_encode(bytes(range(16)))
        with tempfile.TemporaryDirectory() as temp:
            target_root = Path(temp)
            h_cache_root = target_root / "OpenWF" / "Content"
            h_cache_directory = h_cache_root / "0"
            h_cache_directory.mkdir(parents=True)
            (h_cache_directory / repair._h_cache_filename(0xE)).write_bytes(b"captured")

            b_cache_root = target_root / "Content"
            b_cache_directory = b_cache_root / "0"
            b_cache_directory.mkdir(parents=True)
            (b_cache_directory / f"B.Cache.Windows.bin!E_{digest}").write_bytes(b"manifest")

            self.assertEqual(repair.resolve_content_root(target_root), b_cache_root)

    def test_unverified_manifest_coverage_makes_run_incomplete(self) -> None:
        digest = repair.b64m_encode(bytes(range(16)))
        with tempfile.TemporaryDirectory() as temp:
            target_root = Path(temp)
            directory = target_root / "OpenWF" / "Content" / "0"
            directory.mkdir(parents=True)
            (directory / f"B.Cache.Windows.bin!E_{digest}").write_bytes(b"manifest")

            output = io.StringIO()
            with patch.object(
                repair,
                "complete_target_manifests_from_h_cache",
                side_effect=lambda _root, manifests, _oodle: repair.ManifestCoverageResult(
                    manifests, "unverified"
                ),
            ), patch.object(
                repair, "collect_manifest_assets", return_value=([], 0)
            ), patch.object(
                repair, "scan_existing_content_objects", return_value=[]
            ), patch.object(
                repair,
                "_load_packages_parent_index",
                side_effect=repair.RepairError("no Packages metadata"),
            ), patch.object(
                repair, "build_type_resolver", return_value=object()
            ), redirect_stdout(output):
                result = repair.run(target_root, None, patch_types_only=True)

        text = output.getvalue()
        self.assertEqual(result, 1)
        self.assertIn("target B.Cache manifest coverage is unverified", text)
        self.assertNotIn("Repair completed successfully.", text)

    def test_stripped_run_recovers_manifests_only_in_staging(self) -> None:
        windows = bytes(range(16))
        german = bytes(range(16, 32))
        index = repair.HCacheIndex(
            version=13,
            entries={
                "/B.Cache.Windows.bin": windows,
                "/B.Cache.Windows_de.bin": german,
            },
        )

        with tempfile.TemporaryDirectory() as temp:
            target_root = Path(temp) / "patch"
            content_root = target_root / "OpenWF" / "Content"
            directory = content_root / "0"
            directory.mkdir(parents=True)
            manifest_name = f"B.Cache.Windows.bin!E_{repair.b64m_encode(windows)}"
            (directory / manifest_name).write_bytes(b"manifest")
            before = {
                path.relative_to(content_root): path.read_bytes()
                for path in content_root.rglob("*")
                if path.is_file()
            }
            base_root = Path(temp) / "base"
            base_cache = base_root / "Cache.Windows"
            base_cache.mkdir(parents=True)
            (base_cache / "H.Misc.toc").write_bytes(b"")
            output_root = Path(temp) / "stripped"

            def fake_repair_object(**kwargs):
                name = kwargs["name"]
                destination = repair.local_path(kwargs["content_root"], name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"recovered")
                return "downloaded", "CDN", 200

            with patch.object(
                repair, "_matching_h_cache_index", return_value=(index, 0xE)
            ), patch.object(
                repair, "repair_object", side_effect=fake_repair_object
            ), patch.object(
                repair, "collect_manifest_assets", return_value=([], 0)
            ), patch.object(
                repair, "scan_existing_content_objects", return_value=[]
            ), patch.object(
                repair,
                "_load_packages_parent_index",
                side_effect=repair.RepairError("no Packages metadata"),
            ), patch.object(
                repair, "build_type_resolver", return_value=object()
            ), redirect_stdout(io.StringIO()):
                result = repair.run(
                    target_root,
                    base_root,
                    section_mode="only-stripped",
                    stripped_output=output_root,
                )

            after = {
                path.relative_to(content_root): path.read_bytes()
                for path in content_root.rglob("*")
                if path.is_file()
            }

        self.assertEqual(result, 0)
        self.assertEqual(after, before)
        self.assertNotIn(
            Path("0") / f"B.Cache.Windows_de.bin!E_{repair.b64m_encode(german)}",
            after,
        )

    def test_local_h_cache_size_limit_is_enforced_before_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            directory = content_root / "0"
            directory.mkdir()
            h_cache = directory / repair._h_cache_filename(0xE)
            with h_cache.open("wb") as stream:
                stream.truncate(repair.H_CACHE_MAX_RESPONSE_BYTES + 1)

            output = io.StringIO()
            with patch.object(
                repair,
                "_decode_h_cache_object",
                side_effect=AssertionError("oversized local H.Cache must not be decoded"),
            ), redirect_stdout(output):
                result = repair._matching_h_cache_index(content_root, [], object())

        self.assertIsNone(result)
        self.assertIn("safe size limit", output.getvalue())

    def test_run_rejects_invalid_mode_contract_before_work(self) -> None:
        cases = (
            ({"patch_types_only": True, "base_root": Path(".")}, "Base path cannot be combined"),
            ({"patch_types_only": True, "section_mode": "no-stripped"}, "Manifest section filters cannot be combined"),
            ({}, "Base path is required"),
            ({"patch_types_only": True, "section_mode": "invalid"}, "Unknown manifest section mode"),
            ({"patch_types_only": True, "stripped_output": Path("out")}, "Custom stripped output requires only-stripped mode"),
            ({"patch_types_only": True, "download_workers": 0}, "Download workers must be between"),
        )

        with patch.object(
            repair,
            "resolve_content_root",
            side_effect=AssertionError("invalid mode must fail before content discovery"),
        ):
            for kwargs, message in cases:
                with self.subTest(kwargs=kwargs):
                    base_root = kwargs.pop("base_root", None)
                    with self.assertRaisesRegex(repair.RepairError, message):
                        repair.run(Path("."), base_root, **kwargs)

    def test_run_rejects_empty_base_cache_before_manifest_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target_root = root / "patch"
            target_root.mkdir()
            sentinel = target_root / "unchanged.txt"
            sentinel.write_bytes(b"unchanged")
            before = {
                path.relative_to(target_root): path.read_bytes()
                for path in target_root.rglob("*")
                if path.is_file()
            }

            base_root = root / "base"
            (base_root / "Cache.Windows").mkdir(parents=True)
            with patch.object(
                repair,
                "complete_target_manifests_from_h_cache",
                side_effect=AssertionError("manifest completion must not start"),
            ):
                with self.assertRaisesRegex(repair.RepairError, r"contains no usable H\.<package>\.toc files"):
                    repair.run(target_root, base_root)

            after = {
                path.relative_to(target_root): path.read_bytes()
                for path in target_root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

    def test_run_rejects_h_toc_directory_before_manifest_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target_root = root / "patch"
            target_root.mkdir()
            sentinel = target_root / "unchanged.txt"
            sentinel.write_bytes(b"unchanged")
            before = {
                path.relative_to(target_root): path.read_bytes()
                for path in target_root.rglob("*")
                if path.is_file()
            }

            base_root = root / "base"
            cache_dir = base_root / "Cache.Windows"
            cache_dir.mkdir(parents=True)
            (cache_dir / "H.Fake.toc").mkdir()
            with patch.object(
                repair,
                "complete_target_manifests_from_h_cache",
                side_effect=AssertionError("manifest completion must not start"),
            ):
                with self.assertRaisesRegex(repair.RepairError, r"contains no usable H\.<package>\.toc files"):
                    repair.run(target_root, base_root)

            after = {
                path.relative_to(target_root): path.read_bytes()
                for path in target_root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

    def test_run_rejects_empty_package_h_toc_before_manifest_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target_root = root / "patch"
            target_root.mkdir()
            sentinel = target_root / "unchanged.txt"
            sentinel.write_bytes(b"unchanged")
            before = {
                path.relative_to(target_root): path.read_bytes()
                for path in target_root.rglob("*")
                if path.is_file()
            }

            base_root = root / "base"
            cache_dir = base_root / "Cache.Windows"
            cache_dir.mkdir(parents=True)
            (cache_dir / "H..toc").write_bytes(b"")
            with patch.object(
                repair,
                "complete_target_manifests_from_h_cache",
                side_effect=AssertionError("manifest completion must not start"),
            ):
                with self.assertRaisesRegex(repair.RepairError, r"contains no usable H\.<package>\.toc files"):
                    repair.run(target_root, base_root)

            after = {
                path.relative_to(target_root): path.read_bytes()
                for path in target_root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

    def test_run_validates_base_and_openwf_log_before_manifest_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target_root = root / "patch"
            target_root.mkdir()
            missing_base = root / "missing-base"

            with patch.object(
                repair,
                "complete_target_manifests_from_h_cache",
                side_effect=AssertionError("manifest completion must not start"),
            ):
                with self.assertRaisesRegex(repair.RepairError, "Base path is not a directory"):
                    repair.run(target_root, missing_base)

            base_root = root / "base"
            cache_dir = base_root / "Cache.Windows"
            cache_dir.mkdir(parents=True)
            (cache_dir / "H.Misc.toc").write_bytes(b"")
            missing_log = root / "missing-trace.log"
            with patch.object(
                repair,
                "complete_target_manifests_from_h_cache",
                side_effect=AssertionError("manifest completion must not start"),
            ):
                with self.assertRaisesRegex(repair.RepairError, "OpenWF trace log is not a file"):
                    repair.run(target_root, base_root, openwf_log=missing_log)

    def test_openwf_404s_are_scoped_to_latest_session_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "trace.log"

            cases = [
                (
                    "latest session only",
                    "\n".join(
                        [
                            "GET /0/Old.bin!1_AAAA 404",
                            "Using log file: older",
                            "GET /0/Older.bin!2_BBBB 404",
                            "Using log file: current",
                            "GET /0/Current.bin!3_CCCC 404",
                            "GET /0/Current.bin!3_CCCC 404",
                            "GET /9/Shader.hlsl!A_DDDD 404",
                        ]
                    ),
                    ["/0/Current.bin!3_CCCC", "/9/Shader.hlsl!A_DDDD"],
                    2,
                    True,
                ),
                (
                    "no session marker",
                    "\n".join(
                        [
                            "GET /0/Old.bin!1_AAAA 404",
                            "GET /A/Shader.hlsl!B_BBBB 404",
                        ]
                    ),
                    [],
                    2,
                    False,
                ),
            ]

            for label, text, expected_objects, expected_ignored, expected_session in cases:
                with self.subTest(label=label):
                    log_path.write_text(text, encoding="utf-8")
                    objects, ignored, session_found = repair.extract_openwf_missing_objects(log_path)
                    self.assertEqual(objects, expected_objects)
                    self.assertEqual(ignored, expected_ignored)
                    self.assertEqual(session_found, expected_session)

    def test_response_size_limit_rejects_known_and_streamed_oversize_bodies(self) -> None:
        known = FakePycurl([
            {"status": 200, "content_length": 11, "chunks": []},
        ])
        with patch.object(repair, "_pycurl", known), patch.object(
            repair, "_CURL_LOCAL", threading.local()
        ), self.assertRaisesRegex(OSError, "safe size limit"):
            repair._curl_download_bytes(
                "https://example.invalid/H.Cache",
                "H.Cache",
                max_bytes=10,
            )

        streamed = FakePycurl([
            {"status": 200, "chunks": [b"123456", b"789012"]},
        ])
        with patch.object(repair, "_pycurl", streamed), patch.object(
            repair, "_CURL_LOCAL", threading.local()
        ), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OSError, "safe size limit"):
                repair._curl_download_bytes(
                    "https://example.invalid/H.Cache",
                    "H.Cache",
                    max_bytes=10,
                )

    def test_stripped_manifest_staging_does_not_modify_source_metadata(self) -> None:
        digest = repair.b64m_encode(bytes(range(16)))
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp) / "Content"
            directory = content_root / "0"
            directory.mkdir(parents=True)
            manifest_name = f"B.Cache.Windows.bin!E_{digest}"
            h_name = repair._h_cache_filename(0xE)
            (directory / manifest_name).write_bytes(b"manifest")
            (directory / h_name).write_bytes(b"h-cache")

            staging, staged_root = repair._stage_manifest_evidence(content_root)
            try:
                staged_directory = staged_root / "0"
                self.assertEqual((staged_directory / manifest_name).read_bytes(), b"manifest")
                self.assertEqual((staged_directory / h_name).read_bytes(), b"h-cache")
                (staged_directory / "B.Cache.Windows_de.bin!E_extra").write_bytes(b"recovered")
                self.assertFalse((directory / "B.Cache.Windows_de.bin!E_extra").exists())
            finally:
                staging.cleanup()

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

    def test_lzf_decompression_failures_are_strict(self) -> None:
        cases = [
            ("truncated literal run", b"\x02AB", 3, "Truncated LZF literal run"),
            ("truncated extended length", b"\xE0", 1, "Truncated LZF length"),
            ("truncated back-reference", b"\x20", 1, "Truncated LZF back-reference"),
            ("invalid back-reference", b"\x20\x00", 1, "Invalid LZF back-reference"),
            ("wrong decompressed size", b"\x00A", 2, r"LZF produced 1 bytes; expected 2\."),
        ]

        for label, data, expected_size, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(repair.RepairError, message):
                    repair.lzf_decompress(data, expected_size)

    def test_cache_windows_equal_framed_block_is_copied_raw(self) -> None:
        payload = b"raw!"
        num1 = 0x80000000 | (len(payload) << 2)
        num2 = (len(payload) << 5) | 1
        framed = num1.to_bytes(4, "big") + num2.to_bytes(4, "big") + payload

        class RejectOodle:
            def decompress(self, _block: bytes, _expected_size: int) -> bytes:
                raise AssertionError("equal-sized framed block must not use Oodle")

        with tempfile.TemporaryDirectory() as temp:
            cache_path = Path(temp) / "H.Cache.Windows.cache"
            cache_path.write_bytes(framed)
            entry = repair.CacheEntry(
                cache_path=cache_path,
                logical_path="/SyntheticRawBlock",
                offset=0,
                compressed_len=len(framed),
                length=len(payload),
            )

            self.assertEqual(repair.decompress_cache_entry(entry, RejectOodle()), payload)

class FilesystemDiagnosticTests(unittest.TestCase):
    def test_atomic_write_retries_disk_full_without_losing_destination(self) -> None:
        real_mkstemp = repair.tempfile.mkstemp
        real_replace = repair.os.replace

        with self.subTest(stage="temporary creation"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                destination = directory / "asset.bin"
                destination.write_bytes(b"old")
                attempts = 0

                def flaky_mkstemp(*args, **kwargs):
                    nonlocal attempts
                    attempts += 1
                    if attempts == 1:
                        raise OSError(repair.errno.ENOSPC, "synthetic disk full")
                    return real_mkstemp(*args, **kwargs)

                with patch.object(repair, "_wait_for_disk_space") as wait, patch.object(
                    repair.tempfile,
                    "mkstemp",
                    side_effect=flaky_mkstemp,
                ):
                    repair.atomic_write(destination, b"new")

                self.assertEqual(destination.read_bytes(), b"new")
                self.assertEqual(attempts, 2)
                self.assertGreaterEqual(wait.call_count, 2)
                self.assertEqual(list(directory.glob(".wfpr-*.tmp")), [])

        with self.subTest(stage="atomic replacement"):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                destination = directory / "asset.bin"
                destination.write_bytes(b"old")
                attempts = 0

                def flaky_replace(source, target):
                    nonlocal attempts
                    attempts += 1
                    if attempts == 1:
                        self.assertEqual(Path(target).read_bytes(), b"old")
                        raise OSError(repair.errno.ENOSPC, "synthetic disk full")
                    return real_replace(source, target)

                with patch.object(repair, "_wait_for_disk_space") as wait, patch.object(
                    repair.os,
                    "replace",
                    side_effect=flaky_replace,
                ):
                    repair.atomic_write(destination, b"new")

                self.assertEqual(destination.read_bytes(), b"new")
                self.assertEqual(attempts, 2)
                self.assertGreaterEqual(wait.call_count, 2)
                self.assertEqual(list(directory.glob(".wfpr-*.tmp")), [])

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

class DownloadPlanningTests(unittest.TestCase):
    def test_manifest_download_plan_uses_manifest_cdn_size(self) -> None:
        asset = repair.ManifestAsset(
            namespace="0_ja",
            section="service",
            logical_path="/Languages.bin",
            manifest_hash=bytes(range(16)),
            info=0x20000064,
        )
        resolver = repair.TypeResolver(None, None, None)
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            planned, total = repair.plan_manifest_downloads(
                [asset],
                content_root=content_root,
                oodle=object(),
                resolver=resolver,
                base_type_hints={("0_ja", "/Languages.bin"): 0x44},
                base_group_type_hints={},
                openwf_hints={},
            )
        self.assertEqual(len(planned), 1)
        self.assertIs(planned[0], asset)
        self.assertEqual(total, 100)

    def test_manifest_download_plan_excludes_valid_local_object(self) -> None:
        asset = repair.ManifestAsset(
            namespace="0",
            section="packed",
            logical_path="/Example.bin",
            manifest_hash=bytes(range(16)),
            info=0x20000100,
        )
        resolver = repair.TypeResolver(None, None, None)
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            name = repair.cache_name(
                asset.logical_path, 0x44, asset.hash_b64, asset.namespace
            )
            destination = repair.local_path(content_root, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"fixture")
            with patch.object(repair, "verify_shcc", return_value=True):
                planned, total = repair.plan_manifest_downloads(
                    [asset],
                    content_root=content_root,
                    oodle=object(),
                    resolver=resolver,
                    base_type_hints={("0", "/Example.bin"): 0x44},
                    base_group_type_hints={},
                    openwf_hints={},
                )
        self.assertEqual(planned, [])
        self.assertEqual(total, 0)

    def test_manifest_download_plan_caches_verified_local_result(self) -> None:
        asset = repair.ManifestAsset(
            namespace="0",
            section="packed",
            logical_path="/Cached.bin",
            manifest_hash=bytes(range(16)),
            info=0x20000100,
        )
        resolver = repair.TypeResolver(None, None, None)
        cached_results = {}
        with tempfile.TemporaryDirectory() as temp:
            content_root = Path(temp)
            name = repair.cache_name(
                asset.logical_path, 0x44, asset.hash_b64, asset.namespace
            )
            destination = repair.local_path(content_root, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"fixture")
            with patch.object(repair, "verify_shcc", return_value=True) as verifier:
                planned, total = repair.plan_manifest_downloads(
                    [asset],
                    content_root=content_root,
                    oodle=object(),
                    resolver=resolver,
                    base_type_hints={("0", "/Cached.bin"): 0x44},
                    base_group_type_hints={},
                    openwf_hints={},
                    cached_results=cached_results,
                )

        key = (asset.namespace, asset.logical_path, asset.hash_b64)
        self.assertEqual(planned, [])
        self.assertEqual(total, 0)
        self.assertEqual(
            cached_results[key],
            ("present", "original base same-path CommonHeader type hint", name, None),
        )
        verifier.assert_called_once()

    def test_short_download_workers_option_forwards_value(self) -> None:
        argv = ["warframe_patch_repair.py", "patch", "base", "-w", "4"]
        with patch.object(repair.sys, "argv", argv), patch.object(
            repair,
            "run",
            return_value=0,
        ) as runner:
            self.assertEqual(repair.main(), 0)

        self.assertEqual(runner.call_args.kwargs["download_workers"], 4)

    def test_parallel_manifest_downloads_use_two_workers(self) -> None:
        assets = [
            repair.ManifestAsset(
                namespace="0",
                section="packed",
                logical_path=f"/Parallel{index}.bin",
                manifest_hash=bytes([index]) * 16,
                info=0x20000004,
            )
            for index in (1, 2)
        ]
        barrier = threading.Barrier(2)
        worker_names: set[str] = set()
        worker_lock = threading.Lock()

        def fake_repair(asset, **_kwargs):
            with worker_lock:
                worker_names.add(threading.current_thread().name)
            barrier.wait(timeout=2.0)
            name = f"0{asset.logical_path}!44_{asset.hash_b64}"
            return "downloaded", "CDN", name, 200

        progress = repair.OverallDownloadProgress(8, 2)
        with tempfile.TemporaryDirectory() as temp, patch.object(
            repair,
            "repair_manifest_asset",
            side_effect=fake_repair,
        ), redirect_stdout(io.StringIO()):
            root = Path(temp)
            results = repair.repair_planned_manifest_downloads(
                assets,
                content_root=root,
                source_content_root=root,
                oodle=object(),
                resolver=repair.TypeResolver(None, None, None),
                label="Completion",
                base_type_hints={},
                base_group_type_hints={},
                openwf_hints={},
                overall_progress=progress,
                workers=2,
            )

        self.assertEqual(len(results), 2)
        self.assertEqual(len(worker_names), 2)
        self.assertTrue(all(name.startswith("WFPR-CDN") for name in worker_names))

    def test_parallel_manifest_downloads_worker_one_is_sequential(self) -> None:
        assets = [
            repair.ManifestAsset(
                namespace="0",
                section="packed",
                logical_path=f"/Sequential{index}.bin",
                manifest_hash=bytes([index]) * 16,
                info=0x20000004,
            )
            for index in (1, 2)
        ]
        worker_names: list[str] = []

        def fake_repair(asset, **_kwargs):
            worker_names.append(threading.current_thread().name)
            name = f"0{asset.logical_path}!44_{asset.hash_b64}"
            return "downloaded", "CDN", name, 200

        progress = repair.OverallDownloadProgress(8, 2)
        with tempfile.TemporaryDirectory() as temp, patch.object(
            repair,
            "repair_manifest_asset",
            side_effect=fake_repair,
        ), redirect_stdout(io.StringIO()):
            root = Path(temp)
            results = repair.repair_planned_manifest_downloads(
                assets,
                content_root=root,
                source_content_root=root,
                oodle=object(),
                resolver=repair.TypeResolver(None, None, None),
                label="Completion",
                base_type_hints={},
                base_group_type_hints={},
                openwf_hints={},
                overall_progress=progress,
                workers=1,
            )

        self.assertEqual(len(results), 2)
        self.assertEqual(worker_names, [threading.current_thread().name] * 2)

    def test_transient_line_padding_returns_cursor_to_current_frame(self) -> None:
        stream = FakeTTY()
        terminal_size = repair.os.terminal_size((80, 24))
        with patch.object(repair.sys, "stdout", stream), patch.object(
            repair.shutil, "get_terminal_size", return_value=terminal_size
        ):
            line = repair.TransientLine()
            line.render("abcdefghij", "abcdefghij", force=True)
            line.render("abc", "abc", force=True)

        self.assertEqual(stream.getvalue(), "\rabcdefghij\rabc       " + "\b" * 7)

    def test_overall_download_progress_tracks_two_active_workers(self) -> None:
        output = FakeTTY()
        with redirect_stdout(output):
            progress = repair.OverallDownloadProgress(300, 2)
            with patch.object(repair.threading, "get_ident", return_value=101):
                progress.start_attempt("first", 100)
                progress.update(40)
            with patch.object(repair.threading, "get_ident", return_value=202):
                progress.start_attempt("second", 200)
                progress.update(60)

            self.assertEqual(len(progress._active), 2)
            self.assertEqual(sum(item[2] for item in progress._active.values()), 100)
            self.assertEqual(progress.wire_bytes, 100)

            with patch.object(repair.threading, "get_ident", return_value=101):
                progress.commit_attempt(100)
            with patch.object(repair.threading, "get_ident", return_value=202):
                progress.commit_attempt(200)

        self.assertEqual(progress.completed, 300)
        self.assertEqual(progress.files_completed, 2)
        self.assertEqual(progress._active, {})
        self.assertNotIn(" active", output.getvalue())
        self.assertNotIn("first", output.getvalue())
        self.assertNotIn("second", output.getvalue())

    def test_download_asset_global_progress_commits_only_verified_retry(self) -> None:
        fake_curl = FakePycurl([
            {"status": 200, "content_length": 4, "chunks": [b"data"]},
            {"status": 200, "content_length": 4, "chunks": [b"data"]},
        ])
        progress = repair.OverallDownloadProgress(4, 1)
        with patch.object(repair, "_pycurl", fake_curl), patch.object(
            repair, "_CURL_LOCAL", threading.local()
        ), patch.object(
            repair,
            "validate_shcc",
            side_effect=[repair.RepairError("synthetic bad object"), None],
        ) as verifier, patch.object(repair.time, "sleep"), redirect_stdout(io.StringIO()):
            body, error, status = repair.download_asset(
                "https://example.invalid/object",
                display_name="object",
                expected_hash="hash",
                oodle=object(),
                expected_size=4,
                overall_progress=progress,
            )

        self.assertEqual(bytes(body or b""), b"data")
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        self.assertEqual(progress.completed, 4)
        self.assertEqual(progress.wire_bytes, 8)
        self.assertEqual(progress.files_completed, 1)
        self.assertEqual(fake_curl.created, 1)
        self.assertTrue(
            all(call.kwargs["progress_name"] is None for call in verifier.call_args_list)
        )

    def test_libcurl_reuses_thread_handle_without_connection_close(self) -> None:
        fake_curl = FakePycurl([
            {"status": 200, "content_length": 3, "chunks": [b"one"]},
            {"status": 200, "content_length": 3, "chunks": [b"two"]},
        ])
        with patch.object(repair, "_pycurl", fake_curl), patch.object(
            repair, "_CURL_LOCAL", threading.local()
        ), redirect_stdout(io.StringIO()):
            first, first_status = repair._curl_download_bytes(
                "https://example.invalid/one", "one"
            )
            second, second_status = repair._curl_download_bytes(
                "https://example.invalid/two", "two"
            )

        self.assertEqual(bytes(first), b"one")
        self.assertEqual(bytes(second), b"two")
        self.assertEqual((first_status, second_status), (200, 200))
        self.assertEqual(fake_curl.created, 1)
        self.assertEqual(len(fake_curl.handles[0].history), 2)
        for options in fake_curl.handles[0].history:
            self.assertNotIn("Connection: close", options[fake_curl.HTTPHEADER])

    def test_libcurl_redirect_body_does_not_pollute_final_download_or_progress(self) -> None:
        fake_curl = FakePycurl([[
            {"status": 302, "reason": "Found", "content_length": 8, "chunks": [b"redirect"]},
            {"status": 200, "content_length": 4, "chunks": [b"data"]},
        ]])
        progress = repair.OverallDownloadProgress(4, 1)
        with patch.object(repair, "_pycurl", fake_curl), patch.object(
            repair, "_CURL_LOCAL", threading.local()
        ), redirect_stdout(io.StringIO()):
            body, status = repair._curl_download_bytes(
                "https://example.invalid/object",
                "object",
                overall_progress=progress,
                planned_size=4,
            )

        self.assertEqual(bytes(body), b"data")
        self.assertEqual(status, 200)
        self.assertEqual(progress.wire_bytes, 4)
        self.assertEqual(sum(item[2] for item in progress._active.values()), 4)

    def test_libcurl_retries_transient_http_status_on_same_handle(self) -> None:
        fake_curl = FakePycurl([
            {"status": 503, "content_length": 0, "chunks": []},
            {"status": 200, "content_length": 4, "chunks": [b"data"]},
        ])
        progress = repair.OverallDownloadProgress(4, 1)
        with patch.object(repair, "_pycurl", fake_curl), patch.object(
            repair, "_CURL_LOCAL", threading.local()
        ), patch.object(repair, "validate_shcc"), patch.object(
            repair.time, "sleep"
        ), redirect_stdout(io.StringIO()):
            body, error, status = repair.download_asset(
                "https://example.invalid/object",
                display_name="object",
                expected_hash="hash",
                oodle=object(),
                expected_size=4,
                overall_progress=progress,
            )

        self.assertEqual(bytes(body or b""), b"data")
        self.assertIsNone(error)
        self.assertEqual(status, 200)
        self.assertEqual(fake_curl.created, 1)
        self.assertEqual(len(fake_curl.handles[0].history), 2)
        self.assertEqual(progress.completed, 4)
        self.assertEqual(progress.files_completed, 1)

    def test_overall_download_progress_rolls_back_retry_and_adjusts_total(self) -> None:
        with redirect_stdout(io.StringIO()):
            progress = repair.OverallDownloadProgress(300, 2)
            progress.start_attempt("first", 100)
            progress.update(40)
            progress.rollback_attempt()
            self.assertEqual(progress.completed, 0)
            self.assertEqual(progress.wire_bytes, 40)

            progress.start_attempt("first", 100)
            progress.update(120)
            progress.commit_attempt(120)

        self.assertEqual(progress.completed, 120)
        self.assertEqual(progress.total, 320)
        self.assertEqual(progress.files_completed, 1)

    def test_crc32c_known_vector_python_fallback(self) -> None:
        with patch.object(repair, "_google_crc32c", None):
            self.assertEqual(repair.crc32c(b"123456789"), 0xE3069283)

    def test_crc32c_uses_native_google_backend_when_available(self) -> None:
        chunks: list[bytes] = []

        class FakeChecksum:
            def update(self, chunk):
                chunks.append(bytes(chunk))

            def digest(self):
                return (0xE3069283).to_bytes(4, "big")

        class FakeGoogleCRC32C:
            implementation = "c"
            Checksum = FakeChecksum

        with patch.object(repair, "_google_crc32c", FakeGoogleCRC32C):
            result = repair.crc32c(b"123456789ignored", end=9)

        self.assertEqual(result, 0xE3069283)
        self.assertEqual(chunks, [b"123456789"])

    def test_overall_download_message_scope_restores_bottom_progress(self) -> None:
        progress = repair.OverallDownloadProgress(10, 1)
        with patch.object(progress.line, "finish") as finisher, patch.object(
            progress, "_render"
        ) as renderer:
            with progress.message_scope():
                pass

        finisher.assert_called_once()
        renderer.assert_called_once_with(force=True)

    def test_manifest_type_fallback_helper_keeps_priority_order(self) -> None:
        asset = repair.ManifestAsset(
            namespace="A",
            section="packed",
            logical_path="/Synthetic.shader",
            manifest_hash=bytes(range(16)),
            info=0x20000100,
        )
        resolver = repair.TypeResolver(None, None, None)
        with patch.object(
            repair,
            "resolve_manifest_asset_type",
            return_value=(None, None),
        ):
            type_id, source = repair._resolve_manifest_asset_type_with_fallbacks(
                asset,
                resolver=resolver,
                base_type_hint=0x11,
                base_group_type_hint=0x22,
                openwf_type_hint=0x33,
            )

        self.assertEqual(type_id, 0x11)
        self.assertEqual(source, "original base same-path CommonHeader type hint")

    def test_planned_downloads_report_finished_assets_immediately(self) -> None:
        assets = [
            repair.ManifestAsset(
                namespace="0",
                section="packed",
                logical_path=f"/Finished{index}.bin",
                manifest_hash=bytes([index]) * 16,
                info=0x20000004,
            )
            for index in (1, 2)
        ]

        def fake_repair(asset, **_kwargs):
            name = f"0{asset.logical_path}!44_{asset.hash_b64}"
            return "downloaded", "CDN", name, 200

        progress = repair.OverallDownloadProgress(8, 2)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp, patch.object(
            repair,
            "repair_manifest_asset",
            side_effect=fake_repair,
        ), redirect_stdout(output):
            root = Path(temp)
            results = repair.repair_planned_manifest_downloads(
                assets,
                content_root=root,
                source_content_root=root,
                oodle=object(),
                resolver=repair.TypeResolver(None, None, None),
                label="Completion",
                base_type_hints={},
                base_group_type_hints={},
                openwf_hints={},
                overall_progress=progress,
                workers=2,
            )

        self.assertEqual(len(results), 2)
        text = output.getvalue()
        self.assertEqual(text.count("Finished1.bin"), 1)
        self.assertEqual(text.count("Finished2.bin"), 1)

if __name__ == "__main__":
    unittest.main()
