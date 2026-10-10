#!/usr/bin/env python3
"""Analyze U43 manifest `info` metadata against a pre-U43 Cache.Windows base.

Place this file next to the current warframe_patch_repair.py and oo2core_9.dll,
then point it at a research root containing:

- one pre-U43 Cache.Windows directory with H./B./F. .toc + .cache files
- final-U43 B.Cache*.bin!<hash> manifest objects

The helper is read-only. It checks every discovered cache file structurally,
reads/decompresses matching H-cache payloads, compares their leading 16-byte hashes
with the final-U43 manifest hashes, classifies standard CommonHeader versus other
observed H-payload layouts, correlates cache flags 29..31 with H/B/F membership, and audits
size bit 28 using the >256 MiB U43 VideoTexture fixture against cache metadata, CommonHeader
fields, CachePlan.txt and a few size-nearby peer payloads. The hash-confirmed subset is the strongest evidence because it proves
that the pre-U43 H entry is the same asset revision referenced by the U43 manifest.

Outputs are written to <root>\\u43_analysis_output unless --output is supplied.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_repair_module(script: Path):
    if not script.is_file():
        raise SystemExit(f"Repair script not found: {script}")
    spec = importlib.util.spec_from_file_location("wf_repair", script)
    if spec is None or spec.loader is None:
        raise SystemExit(f"Could not load repair script: {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def find_manifests(root: Path, repair):
    found = []
    seen_identity = {}
    for path in root.rglob("B.Cache*.bin!*"):
        if not path.is_file():
            continue
        match = repair.MANIFEST_RE.fullmatch(path.name)
        if match is None:
            continue
        identity = (match.group("kind"), match.group("suffix") or "")
        previous = seen_identity.get(identity)
        if previous is not None:
            raise SystemExit(
                "Multiple manifests for the same family were found:\n"
                f"  {previous}\n  {path}\n"
                "Remove stale manifests from other builds or point the helper at a cleaner folder."
            )
        seen_identity[identity] = path
        found.append((path, match))
    return sorted(found, key=lambda item: item[0].name.casefold())


def find_content_root(manifests) -> Path | None:
    """Return the single OpenWF/Content root containing the discovered manifests."""
    roots = set()
    for path, _match in manifests:
        parent = path.parent
        if parent.name == "0" and parent.parent.name == "Content":
            roots.add(parent.parent.resolve())
    return next(iter(roots)) if len(roots) == 1 else None


def observed_target_types(content_root: Path | None, repair):
    """Map exact target namespace/path observations to the CDN type IDs in filenames."""
    result = defaultdict(set)
    if content_root is None:
        return result
    for observation in repair.scan_existing_content_objects(content_root):
        result[(observation.namespace, normalize_path(observation.logical_path))].add(
            observation.type_id
        )
    return result


def find_cache_dir(root: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        cache_dir = explicit.resolve()
        if not cache_dir.is_dir():
            raise SystemExit(f"Cache.Windows directory does not exist: {cache_dir}")
        return cache_dir

    candidates = []
    if root.name.casefold() == "cache.windows" and root.is_dir():
        candidates.append(root)
    for path in root.rglob("Cache.Windows"):
        if path.is_dir() and path not in candidates and any(path.glob("H.*.toc")):
            candidates.append(path)

    if not candidates:
        raise SystemExit(f"No Cache.Windows directory with H.*.toc files found below: {root}")
    if len(candidates) > 1:
        text = "\n".join(f"  {path}" for path in candidates)
        raise SystemExit(
            "Multiple Cache.Windows directories were found:\n"
            f"{text}\n"
            "Use --cache-dir to select the pre-U43 Steam-base Cache.Windows directory."
        )
    return candidates[0]


def find_tocs(cache_dir: Path):
    return sorted(
        (
            p
            for p in cache_dir.glob("*.toc")
            if p.is_file() and len(p.name) > 2 and p.name[:2] in {"H.", "B.", "F."}
        ),
        key=lambda p: p.name.casefold(),
    )


def normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    return path if path.startswith("/") else "/" + path


def package_from_toc(toc: Path) -> str:
    return toc.name[2:-4]


def namespace_from_package(package: str, repair) -> str:
    return repair._cache_namespace_from_package(package)


def namespace_for_match(match) -> str:
    kind = match.group("kind")
    suffix = match.group("suffix") or ""
    if kind == "Windows":
        return "0" + suffix
    if kind == "Dx11":
        return "9"
    return "A"


def membership_label(splits) -> str:
    return "+".join(x for x in "HBF" if x in splits) or "none"


def toc_index_and_cache_validation(tocs, repair):
    memberships = defaultdict(set)
    entries_by_key = defaultdict(lambda: defaultdict(list))
    packages_by_key = defaultdict(lambda: defaultdict(set))
    split_unique = {"H": set(), "B": set(), "F": set()}
    toc_versions = Counter()
    toc_errors = []
    cache_rows = []

    for toc in tocs:
        split = toc.name[0]
        package = package_from_toc(toc)
        namespace = namespace_from_package(package, repair)
        cache_path = toc.with_suffix(".cache")
        try:
            cache_size = cache_path.stat().st_size
            cache_exists = True
            cache_error = ""
        except OSError as exc:
            cache_size = None
            cache_exists = False
            cache_error = str(exc)

        entry_count = 0
        bounds_ok = 0
        bounds_bad = 0
        total_compressed = 0
        total_logical = 0
        max_end = 0

        try:
            data = toc.read_bytes()
            if len(data) >= 8:
                _magic, version = repair.struct.unpack_from("<II", data, 0)
                toc_versions[version] += 1

            for entry in repair.iter_toc_entries(toc):
                entry_count += 1
                logical = normalize_path(entry.logical_path)
                key = (namespace, logical)
                memberships[key].add(split)
                entries_by_key[key][split].append(entry)
                packages_by_key[key][split].add(package)
                split_unique[split].add(key)
                total_compressed += entry.compressed_len
                total_logical += entry.length
                end = entry.offset + entry.compressed_len
                max_end = max(max_end, end)
                if cache_size is not None and entry.offset <= cache_size and entry.compressed_len <= cache_size - entry.offset:
                    bounds_ok += 1
                else:
                    bounds_bad += 1
        except Exception as exc:
            toc_errors.append((toc, str(exc)))

        cache_rows.append(
            {
                "split": split,
                "package": package,
                "namespace": namespace,
                "toc": toc,
                "cache": cache_path,
                "cache_exists": cache_exists,
                "cache_size": cache_size,
                "entries": entry_count,
                "bounds_ok": bounds_ok,
                "bounds_bad": bounds_bad,
                "max_entry_end": max_end,
                "total_compressed": total_compressed,
                "total_logical": total_logical,
                "error": cache_error,
            }
        )

    return (
        memberships,
        entries_by_key,
        packages_by_key,
        split_unique,
        toc_versions,
        toc_errors,
        cache_rows,
    )


def read_h_headers_for_targets(
    assets,
    entries_by_key,
    packages_by_key,
    repair,
    oodle,
    exact_target_types,
):
    target_hashes = defaultdict(set)
    target_sections = defaultdict(set)
    target_nibbles = defaultdict(set)
    for _manifest, namespace, section, path, manifest_hash, info, _version in assets:
        key = (namespace, path)
        target_hashes[key].add(manifest_hash)
        target_sections[key].add(section)
        target_nibbles[key].add((info >> 28) & 0xF)

    target_keys = [key for key in target_hashes if entries_by_key.get(key, {}).get("H")]
    results = {}
    error_counts = Counter()
    type_unavailable = Counter()
    layout_counts = Counter()
    unavailable_with_exact_target_type = 0

    print(f"  H payload target keys: {len(target_keys):,}")
    for index, key in enumerate(target_keys, 1):
        namespace, path = key
        rows = []
        sections = target_sections.get(key, set())
        nibbles = target_nibbles.get(key, set())
        observed_types = exact_target_types.get(key, set())
        observed_type_text = ";".join(f"{type_id:X}" for type_id in sorted(observed_types))
        for entry in entries_by_key[key]["H"]:
            row = {
                "cache": entry.cache_path.name,
                "package": entry.cache_path.name[2:-6] if entry.cache_path.name.startswith("H.") else entry.cache_path.stem,
                "offset": entry.offset,
                "compressed_len": entry.compressed_len,
                "length": entry.length,
                "hash_b64": "",
                "type_id": "",
                "type_layout": "",
                "type_parse_reason": "",
                "target_sections": ";".join(sorted(sections)),
                "target_upper_nibbles": ";".join(f"0x{nibble:X}" for nibble in sorted(nibbles)),
                "target_observed_type_ids": observed_type_text,
                "read_ok": False,
                "hash_matches_any_target": False,
                "error": "",
            }
            try:
                payload = repair.decompress_cache_entry(entry, oodle)
                if len(payload) < 16:
                    raise repair.RepairError("H-cache payload is too short to contain the manifest hash.")
                header_hash = bytes(payload[:16])
                row["hash_b64"] = repair.b64m_encode(header_hash)
                row["read_ok"] = True
                row["hash_matches_any_target"] = header_hash in target_hashes[key]
                try:
                    _parsed_hash, type_id = repair.parse_common_header(payload)
                    row["type_id"] = type_id
                    row["type_layout"] = "common_header"
                    layout_counts["common_header"] += 1
                except Exception as exc:
                    reason = str(exc).replace("\r", " ").replace("\n", " ")
                    row["type_parse_reason"] = reason
                    # A service manifest entry is intentionally treated as a special
                    # payload before shape heuristics. Packages.bin, Dependancies.bin
                    # and Languages.bin are real examples in this U43 fixture.
                    if "service" in sections:
                        layout = "service_payload"
                    elif len(payload) > 16 and (len(payload) - 1) % 16 == 0:
                        # Observed for the large MissionDeck/DropTable/reward-manifest
                        # family. This is a structural label only; it does not claim
                        # that the 16-byte chunks have been semantically decoded.
                        layout = "opaque_16n_plus_1"
                    else:
                        layout = "non_commonheader_payload"
                    row["type_layout"] = layout
                    layout_counts[layout] += 1
                    type_unavailable[(layout, entry.cache_path.name, reason)] += 1
                    if observed_types:
                        unavailable_with_exact_target_type += 1
            except Exception as exc:
                reason = str(exc).replace("\r", " ").replace("\n", " ")
                row["error"] = reason
                error_counts[(entry.cache_path.name, reason)] += 1
            rows.append(row)
        results[key] = rows
        if index == 1 or index % 2000 == 0 or index == len(target_keys):
            print(f"  H payloads: {index:,}/{len(target_keys):,}")

    return (
        results,
        error_counts,
        type_unavailable,
        layout_counts,
        unavailable_with_exact_target_type,
    )


def summarize_h_status(rows, target_hash: bytes, repair):
    if not rows:
        return "absent", "", "", ""
    readable = [row for row in rows if row["read_ok"]]
    if not readable:
        return "read_error", "", "", ";".join(sorted({row["cache"] for row in rows}))

    target_b64 = repair.b64m_encode(target_hash)
    hashes = sorted({row["hash_b64"] for row in readable if row["hash_b64"]})
    types = sorted({str(row["type_id"]) for row in readable if row["type_id"] != ""})
    caches = sorted({row["cache"] for row in readable})
    matches = [row for row in readable if row["hash_b64"] == target_b64]
    status = "match" if matches else "mismatch"
    return status, ";".join(hashes), ";".join(types), ";".join(caches)


def write_cache_validation(path: Path, cache_rows):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "split",
                "package",
                "namespace",
                "toc",
                "cache",
                "cache_exists",
                "cache_size",
                "entries",
                "bounds_ok",
                "bounds_bad",
                "max_entry_end",
                "total_compressed",
                "total_logical",
                "error",
            ]
        )
        for row in cache_rows:
            writer.writerow(
                [
                    row["split"],
                    row["package"],
                    row["namespace"],
                    row["toc"].name,
                    row["cache"].name,
                    int(row["cache_exists"]),
                    "" if row["cache_size"] is None else row["cache_size"],
                    row["entries"],
                    row["bounds_ok"],
                    row["bounds_bad"],
                    row["max_entry_end"],
                    row["total_compressed"],
                    row["total_logical"],
                    row["error"],
                ]
            )



def inspect_common_header_details(payload: bytes, repair) -> dict:
    """Research-only expansion of the CommonHeader fields used by the repairer."""
    result = {
        "source_path_count": "",
        "source_paths": "",
        "attribute_len": "",
        "attribute_hex": "",
        "attribute_text": "",
        "attribute_terminator_hex": "",
        "raw_type_field_hex": "",
        "type_id": "",
        "trailing_len": "",
        "trailing_hex": "",
        "parse_error": "",
    }
    try:
        if len(payload) < 24:
            raise repair.RepairError("CommonHeader is too short.")
        offset = 16
        source_path_count = repair.struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if source_path_count > 3000:
            raise repair.RepairError(
                f"Unreasonable CommonHeader source path count: {source_path_count}"
            )
        source_paths = []
        for _ in range(source_path_count):
            if offset + 4 > len(payload):
                raise repair.RepairError("Truncated CommonHeader source-path length.")
            path_len = repair.struct.unpack_from("<I", payload, offset)[0]
            offset += 4
            if path_len > 200 or offset + path_len > len(payload):
                raise repair.RepairError("Invalid CommonHeader source path.")
            raw = payload[offset : offset + path_len]
            offset += path_len
            try:
                source_paths.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                source_paths.append(raw.decode("latin-1", errors="replace"))

        if offset + 4 > len(payload):
            raise repair.RepairError("Truncated CommonHeader attribute length.")
        attribute_len = repair.struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if offset + attribute_len > len(payload):
            raise repair.RepairError("Truncated CommonHeader attributes.")
        attributes = bytes(payload[offset : offset + attribute_len])
        offset += attribute_len

        terminator = b""
        if attribute_len > 0:
            if offset >= len(payload):
                raise repair.RepairError("Truncated CommonHeader attribute terminator.")
            terminator = bytes(payload[offset : offset + 1])
            offset += 1

        if offset + 4 > len(payload):
            raise repair.RepairError("Truncated CommonHeader type.")
        raw_type = repair.struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        trailing = bytes(payload[offset:])

        def printable(raw: bytes, limit: int = 512) -> str:
            raw = raw[:limit]
            text = raw.decode("utf-8", errors="replace")
            return "".join(ch if ch.isprintable() else "." for ch in text)

        result.update(
            {
                "source_path_count": source_path_count,
                "source_paths": " | ".join(source_paths),
                "attribute_len": attribute_len,
                "attribute_hex": attributes[:512].hex(),
                "attribute_text": printable(attributes),
                "attribute_terminator_hex": terminator.hex(),
                "raw_type_field_hex": f"0x{raw_type:08X}",
                "type_id": raw_type & 0xFFFF,
                "trailing_len": len(trailing),
                "trailing_hex": trailing[:256].hex(),
            }
        )
    except Exception as exc:
        result["parse_error"] = str(exc).replace("\r", " ").replace("\n", " ")
    return result


def _entry_fields(entries) -> dict:
    entries = list(entries or [])
    if not entries:
        return {
            "cache_files": "",
            "entry_count": 0,
            "offsets": "",
            "compressed_lens": "",
            "logical_lens": "",
        }
    return {
        "cache_files": ";".join(sorted({entry.cache_path.name for entry in entries})),
        "entry_count": len(entries),
        "offsets": ";".join(str(entry.offset) for entry in entries),
        "compressed_lens": ";".join(str(entry.compressed_len) for entry in entries),
        "logical_lens": ";".join(str(entry.length) for entry in entries),
    }


def _find_cacheplans(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_file() and path.name.casefold() == "cacheplan.txt"),
        key=lambda path: str(path).casefold(),
    )


def _read_text_best_effort(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def write_cacheplan_probe(path: Path, root: Path, candidates) -> int:
    plans = _find_cacheplans(root)
    hits = 0
    with path.open("w", encoding="utf-8") as f:
        f.write("size bit 28 CachePlan probe\n")
        f.write("======================\n\n")
        if not plans:
            f.write("No CachePlan.txt found below the research root.\n")
            return 0
        for plan in plans:
            try:
                lines = _read_text_best_effort(plan).splitlines()
            except OSError as exc:
                f.write(f"CachePlan: {plan}\nERROR: {exc}\n\n")
                continue
            f.write(f"CachePlan: {plan}\n")
            for candidate in candidates:
                logical_path = candidate[3]
                basename = Path(logical_path).name
                needles = {
                    logical_path.casefold(),
                    logical_path.lstrip("/").casefold(),
                    basename.casefold(),
                }
                matches = []
                for index, line in enumerate(lines):
                    folded = line.casefold()
                    if any(needle and needle in folded for needle in needles):
                        matches.append(index)
                f.write(f"\nCandidate: {logical_path}\n")
                f.write(f"Matches: {len(matches)}\n")
                for index in matches:
                    hits += 1
                    start = max(0, index - 4)
                    stop = min(len(lines), index + 5)
                    f.write(f"--- lines {start + 1}-{stop} (match at {index + 1}) ---\n")
                    for line_no in range(start, stop):
                        marker = ">" if line_no == index else " "
                        f.write(f"{marker}{line_no + 1:8d}: {lines[line_no]}\n")
            f.write("\n\n")
    return hits


def _payload_sample_row(namespace, path, split, entry, repair, oodle, *, decode_limit=16 * 1024 * 1024):
    row = {
        "namespace": namespace,
        "path": path,
        "split": split,
        "cache": entry.cache_path.name,
        "offset": entry.offset,
        "compressed_len": entry.compressed_len,
        "logical_len": entry.length,
        "decoded_len": "",
        "sha256": "",
        "head64_hex": "",
        "tail64_hex": "",
        "decode_status": "",
    }
    if entry.length > decode_limit:
        row["decode_status"] = f"skipped: logical length exceeds {decode_limit}"
        return row
    try:
        payload = repair.decompress_cache_entry(entry, oodle)
        row["decoded_len"] = len(payload)
        row["sha256"] = hashlib.sha256(payload).hexdigest()
        row["head64_hex"] = payload[:64].hex()
        row["tail64_hex"] = payload[-64:].hex() if payload else ""
        row["decode_status"] = "ok"
    except Exception as exc:
        row["decode_status"] = "error: " + str(exc).replace("\r", " ").replace("\n", " ")
    return row


def probe_compare_manifest_dirs(compare_dirs, candidate_paths, repair, oodle):
    rows = []
    wanted = {normalize_path(path) for path in candidate_paths}
    for raw_dir in compare_dirs:
        directory = raw_dir.resolve()
        if not directory.is_dir():
            rows.append(
                {
                    "build": directory.name,
                    "directory": str(directory),
                    "manifest": "",
                    "namespace": "",
                    "section": "",
                    "path": "",
                    "info_hex": "",
                    "cdn_size": "",
                    "upper_nibble_hex": "",
                    "bit28": "",
                    "error": "directory does not exist",
                }
            )
            continue
        try:
            manifests = find_manifests(directory, repair)
        except SystemExit as exc:
            rows.append(
                {
                    "build": directory.name,
                    "directory": str(directory),
                    "manifest": "",
                    "namespace": "",
                    "section": "",
                    "path": "",
                    "info_hex": "",
                    "cdn_size": "",
                    "upper_nibble_hex": "",
                    "bit28": "",
                    "error": str(exc).replace("\r", " ").replace("\n", " "),
                }
            )
            continue
        for manifest_path, match in manifests:
            try:
                data = manifest_path.read_bytes()
                header, digest = repair.shcc_header_and_hash(data, oodle, progress_name=manifest_path.name)
                actual_hash = repair.b64m_encode(digest)
                expected_hash = match.group("hash")
                if actual_hash != expected_hash:
                    raise repair.RepairError(
                        f"SHCC hash mismatch: expected {expected_hash}, got {actual_hash}"
                    )
                namespace = namespace_for_match(match)
                for section, logical_path, _manifest_hash, info in repair.parse_manifest_header(header):
                    logical_path = normalize_path(logical_path)
                    if logical_path not in wanted:
                        continue
                    rows.append(
                        {
                            "build": directory.name,
                            "directory": str(directory),
                            "manifest": manifest_path.name,
                            "namespace": namespace,
                            "section": section,
                            "path": logical_path,
                            "info_hex": f"0x{info:08X}",
                            "cdn_size": info & repair.MANIFEST_INFO_SIZE_MASK,
                            "upper_nibble_hex": f"0x{((info >> 28) & 0xF):X}",
                            "bit28": (info >> 28) & 1,
                            "error": "",
                        }
                    )
            except Exception as exc:
                rows.append(
                    {
                        "build": directory.name,
                        "directory": str(directory),
                        "manifest": manifest_path.name,
                        "namespace": "",
                        "section": "",
                        "path": "",
                        "info_hex": "",
                        "cdn_size": "",
                        "upper_nibble_hex": "",
                        "bit28": "",
                        "error": str(exc).replace("\r", " ").replace("\n", " "),
                    }
                )
    return rows


def write_bit28_research(
    out_dir: Path,
    root: Path,
    assets,
    memberships,
    entries_by_key,
    packages_by_key,
    h_results,
    exact_target_types,
    repair,
    oodle,
    compare_manifest_dirs,
):
    # Bit 28 is now proven to be size bit 28; these are >256 MiB manifest objects.
    candidates = [asset for asset in assets if (asset[5] >> 28) & 1]
    candidate_csv = out_dir / "u43_bit28_candidates.csv"
    peer_csv = out_dir / "u43_bit28_peer_comparison.csv"
    payload_csv = out_dir / "u43_bit28_payload_samples.csv"
    cacheplan_txt = out_dir / "u43_bit28_cacheplan_matches.txt"
    cross_build_csv = out_dir / "u43_bit28_cross_build.csv"

    with candidate_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "manifest", "namespace", "section", "path", "hash_b64", "info_hex",
                "cdn_size", "upper_nibble_hex", "bit28", "bit29", "bit30", "bit31",
                "base_membership", "base_H_packages", "base_B_packages", "base_F_packages",
                "h_target_hash_status", "base_H_type_ids", "target_observed_type_ids",
            ]
        )
        for manifest, namespace, section, logical_path, manifest_hash, info, _version in candidates:
            key = (namespace, logical_path)
            h_status, _hashes, h_types, _caches = summarize_h_status(
                h_results.get(key, []), manifest_hash, repair
            )
            observed = exact_target_types.get(key, set())
            writer.writerow(
                [
                    manifest, namespace, section, logical_path, repair.b64m_encode(manifest_hash),
                    f"0x{info:08X}", info & repair.MANIFEST_INFO_SIZE_MASK,
                    f"0x{((info >> 28) & 0xF):X}",
                    *tuple((info >> bit) & 1 for bit in range(28, 32)),
                    membership_label(memberships.get(key, set())),
                    ";".join(sorted(packages_by_key.get(key, {}).get("H", set()))),
                    ";".join(sorted(packages_by_key.get(key, {}).get("B", set()))),
                    ";".join(sorted(packages_by_key.get(key, {}).get("F", set()))),
                    h_status, h_types,
                    ";".join(f"{type_id:X}" for type_id in sorted(observed)),
                ]
            )

    peer_rows = []
    sample_keys = set()
    for candidate in candidates:
        _manifest, namespace, section, candidate_path, _manifest_hash, candidate_info, _version = candidate
        candidate_key = (namespace, candidate_path)
        suffix = Path(candidate_path).suffix.casefold()
        candidate_membership = membership_label(memberships.get(candidate_key, set()))
        candidate_h_packages = packages_by_key.get(candidate_key, {}).get("H", set())
        candidate_size = candidate_info & repair.MANIFEST_INFO_SIZE_MASK

        compatible = []
        for asset in assets:
            _m, ns, sec, logical_path, _h, info, _v = asset
            if ns != namespace or sec != section:
                continue
            if Path(logical_path).suffix.casefold() != suffix:
                continue
            key = (ns, logical_path)
            if membership_label(memberships.get(key, set())) != candidate_membership:
                continue
            h_packages = packages_by_key.get(key, {}).get("H", set())
            if candidate_h_packages and not (candidate_h_packages & h_packages):
                continue
            compatible.append(asset)

        compatible.sort(
            key=lambda asset: (
                abs((asset[5] & repair.MANIFEST_INFO_SIZE_MASK) - candidate_size),
                asset[3].casefold(),
            )
        )
        sample_keys.add(candidate_key)
        for asset in compatible:
            key = (asset[1], asset[3])
            if key != candidate_key and len([k for k in sample_keys if k != candidate_key]) < 4:
                sample_keys.add(key)

            h_entries = entries_by_key.get(key, {}).get("H", [])
            b_entries = entries_by_key.get(key, {}).get("B", [])
            f_entries = entries_by_key.get(key, {}).get("F", [])
            h_fields = _entry_fields(h_entries)
            b_fields = _entry_fields(b_entries)
            f_fields = _entry_fields(f_entries)
            details = {}
            if h_entries:
                try:
                    payload = repair.decompress_cache_entry(h_entries[0], oodle)
                    details = inspect_common_header_details(payload, repair)
                except Exception as exc:
                    details = {"parse_error": str(exc).replace("\r", " ").replace("\n", " ")}
            observed = exact_target_types.get(key, set())
            info = asset[5]
            peer_rows.append(
                {
                    "candidate_path": candidate_path,
                    "is_candidate": int(key == candidate_key),
                    "size_distance": abs((info & repair.MANIFEST_INFO_SIZE_MASK) - candidate_size),
                    "path": asset[3],
                    "section": asset[2],
                    "cdn_size": info & repair.MANIFEST_INFO_SIZE_MASK,
                    "upper_nibble_hex": f"0x{((info >> 28) & 0xF):X}",
                    "bit28": (info >> 28) & 1,
                    "membership": membership_label(memberships.get(key, set())),
                    "h_packages": ";".join(sorted(packages_by_key.get(key, {}).get("H", set()))),
                    "b_packages": ";".join(sorted(packages_by_key.get(key, {}).get("B", set()))),
                    "f_packages": ";".join(sorted(packages_by_key.get(key, {}).get("F", set()))),
                    "target_observed_type_ids": ";".join(f"{x:X}" for x in sorted(observed)),
                    "h_cache_files": h_fields["cache_files"],
                    "h_compressed_lens": h_fields["compressed_lens"],
                    "h_logical_lens": h_fields["logical_lens"],
                    "b_cache_files": b_fields["cache_files"],
                    "b_compressed_lens": b_fields["compressed_lens"],
                    "b_logical_lens": b_fields["logical_lens"],
                    "f_cache_files": f_fields["cache_files"],
                    "f_compressed_lens": f_fields["compressed_lens"],
                    "f_logical_lens": f_fields["logical_lens"],
                    "source_path_count": details.get("source_path_count", ""),
                    "source_paths": details.get("source_paths", ""),
                    "attribute_len": details.get("attribute_len", ""),
                    "attribute_hex": details.get("attribute_hex", ""),
                    "attribute_text": details.get("attribute_text", ""),
                    "attribute_terminator_hex": details.get("attribute_terminator_hex", ""),
                    "raw_type_field_hex": details.get("raw_type_field_hex", ""),
                    "h_type_id": details.get("type_id", ""),
                    "trailing_len": details.get("trailing_len", ""),
                    "trailing_hex": details.get("trailing_hex", ""),
                    "common_header_detail_error": details.get("parse_error", ""),
                }
            )

    peer_fields = [
        "candidate_path", "is_candidate", "size_distance", "path", "section", "cdn_size",
        "upper_nibble_hex", "bit28", "membership", "h_packages", "b_packages", "f_packages",
        "target_observed_type_ids", "h_cache_files", "h_compressed_lens", "h_logical_lens",
        "b_cache_files", "b_compressed_lens", "b_logical_lens", "f_cache_files",
        "f_compressed_lens", "f_logical_lens", "source_path_count", "source_paths",
        "attribute_len", "attribute_hex", "attribute_text", "attribute_terminator_hex",
        "raw_type_field_hex", "h_type_id", "trailing_len", "trailing_hex",
        "common_header_detail_error",
    ]
    with peer_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=peer_fields)
        writer.writeheader()
        writer.writerows(peer_rows)

    payload_rows = []
    for key in sorted(sample_keys):
        namespace, logical_path = key
        for split in ("H", "B", "F"):
            for entry in entries_by_key.get(key, {}).get(split, []):
                payload_rows.append(
                    _payload_sample_row(namespace, logical_path, split, entry, repair, oodle)
                )
    payload_fields = [
        "namespace", "path", "split", "cache", "offset", "compressed_len", "logical_len",
        "decoded_len", "sha256", "head64_hex", "tail64_hex", "decode_status",
    ]
    with payload_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=payload_fields)
        writer.writeheader()
        writer.writerows(payload_rows)

    cacheplan_hits = write_cacheplan_probe(cacheplan_txt, root, candidates)

    compare_rows = probe_compare_manifest_dirs(
        compare_manifest_dirs,
        [candidate[3] for candidate in candidates],
        repair,
        oodle,
    ) if compare_manifest_dirs else []
    cross_fields = [
        "build", "directory", "manifest", "namespace", "section", "path", "info_hex",
        "cdn_size", "upper_nibble_hex", "bit28", "error",
    ]
    with cross_build_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=cross_fields)
        writer.writeheader()
        writer.writerows(compare_rows)

    return {
        "candidates": len(candidates),
        "peer_rows": len(peer_rows),
        "payload_rows": len(payload_rows),
        "cacheplan_hits": cacheplan_hits,
        "compare_rows": len(compare_rows),
        "paths": [candidate_csv, peer_csv, payload_csv, cacheplan_txt, cross_build_csv],
    }

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Dump U43 B.Cache manifest info fields and correlate them with pre-U43 H/B/F "
            "Cache.Windows TOCs and cache payload evidence."
        )
    )
    parser.add_argument("root", type=Path, help="Research root containing the base Cache.Windows and U43 manifests")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="Explicit pre-U43 Cache.Windows directory (required only if multiple are below root)",
    )
    parser.add_argument(
        "--repair-script",
        type=Path,
        default=Path(__file__).resolve().with_name("warframe_patch_repair.py"),
        help="Path to the current warframe_patch_repair.py",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory (default: <root>/u43_analysis_output)",
    )
    parser.add_argument(
        "--skip-h-cache-read",
        action="store_true",
        help="Skip H-cache payload decompression/hash comparison (structural .cache checks still run)",
    )
    parser.add_argument(
        "--compare-manifest-dir",
        type=Path,
        action="append",
        default=[],
        help=(
            "Optional additional build directory containing extracted B.Cache manifest objects. "
            "May be repeated; bit-28 candidate paths are probed there for cross-build comparison."
        ),
    )
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"Root folder does not exist: {root}")

    repair_script = args.repair_script.resolve()
    repair = load_repair_module(repair_script)
    dll = repair_script.with_name(repair.OODLE_DLL_NAME)
    if not dll.is_file():
        raise SystemExit(
            f"{repair.OODLE_DLL_NAME} was not found next to the repair script:\n  {dll}\n"
            "Use the complete repair-script bundle."
        )

    cache_dir = find_cache_dir(root, args.cache_dir)
    manifests = find_manifests(root, repair)
    if not manifests:
        raise SystemExit(f"No supported B.Cache manifest objects found below: {root}")

    tocs = find_tocs(cache_dir)
    if not tocs:
        raise SystemExit(f"No H./B./F. TOCs found in: {cache_dir}")

    content_root = find_content_root(manifests)
    exact_target_types = observed_target_types(content_root, repair)

    out_dir = (args.output or (root / "u43_analysis_output")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Root       : {root}")
    print(f"Cache      : {cache_dir}")
    print(f"Repair     : {repair_script}")
    print(f"Oodle      : {dll}")
    print(f"Manifests  : {len(manifests)}")
    print(f"TOCs       : {len(tocs)}")
    if content_root is not None:
        print(f"Content    : {content_root}")
        print(f"Objects    : {sum(len(v) for v in exact_target_types.values()):,} exact target type observations")
    else:
        print("Content    : not uniquely identified; exact target type observations unavailable")
    print(f"Output     : {out_dir}")
    print()

    print("[1/5] Indexing TOCs and validating every .cache file/range...")
    (
        memberships,
        entries_by_key,
        packages_by_key,
        split_unique,
        toc_versions,
        toc_errors,
        cache_rows,
    ) = toc_index_and_cache_validation(tocs, repair)

    missing_caches = [row for row in cache_rows if not row["cache_exists"]]
    bad_bounds = sum(row["bounds_bad"] for row in cache_rows)
    if toc_errors:
        print(f"WARNING: {len(toc_errors)} TOC(s) could not be parsed.")
        for path, error in toc_errors[:10]:
            print(f"  {path}: {error}")
        if len(toc_errors) > 10:
            print(f"  ... and {len(toc_errors) - 10} more")
    if missing_caches:
        print(f"WARNING: {len(missing_caches)} matching .cache file(s) are missing.")
    if bad_bounds:
        print(f"WARNING: {bad_bounds:,} TOC entries exceed their .cache file bounds.")

    base_class_counts = Counter(membership_label(splits) for splits in memberships.values())
    print(
        "  Unique namespace+paths: "
        f"H={len(split_unique['H']):,} | B={len(split_unique['B']):,} | F={len(split_unique['F']):,}"
    )
    print("  Membership: " + " | ".join(f"{k}={v:,}" for k, v in sorted(base_class_counts.items())))
    print(
        f"  Cache files: {len(cache_rows)} | missing={len(missing_caches)} | "
        f"out-of-bounds entries={bad_bounds:,}"
    )

    print("[2/5] Decoding final-U43 B.Cache manifests with Oodle...")
    oodle = repair.Oodle()
    assets = []
    manifest_failures = 0
    for manifest_path, match in manifests:
        try:
            data = manifest_path.read_bytes()
            header, digest = repair.shcc_header_and_hash(data, oodle, progress_name=manifest_path.name)
            actual_hash = repair.b64m_encode(digest)
            expected_hash = match.group("hash")
            if actual_hash != expected_hash:
                raise repair.RepairError(f"SHCC hash mismatch: expected {expected_hash}, got {actual_hash}")
            version = repair._manifest_header_version(header)
            namespace = namespace_for_match(match)
            count = 0
            for section, logical_path, manifest_hash, info in repair.parse_manifest_header(header):
                assets.append(
                    (
                        manifest_path.name,
                        namespace,
                        section,
                        normalize_path(logical_path),
                        manifest_hash,
                        info,
                        version,
                    )
                )
                count += 1
            print(f"  {manifest_path.name}: v{version}, {count:,} entries")
        except Exception as exc:
            manifest_failures += 1
            print(f"ERROR: {manifest_path.name}: {exc}")

    if manifest_failures:
        raise SystemExit(f"Stopped: {manifest_failures} manifest(s) failed to decode.")
    print(f"  Total manifest entries: {len(assets):,}")

    h_results = {}
    h_read_errors = Counter()
    h_type_unavailable = Counter()
    h_layout_counts = Counter()
    h_unavailable_with_exact_target_type = 0
    if args.skip_h_cache_read:
        print("[3/5] H-cache payload read skipped by --skip-h-cache-read.")
    else:
        print("[3/5] Reading matching H-cache payloads and comparing target hashes...")
        (
            h_results,
            h_read_errors,
            h_type_unavailable,
            h_layout_counts,
            h_unavailable_with_exact_target_type,
        ) = read_h_headers_for_targets(
            assets,
            entries_by_key,
            packages_by_key,
            repair,
            oodle,
            exact_target_types,
        )
        if h_read_errors:
            print(f"WARNING: {sum(h_read_errors.values()):,} H payload read/decompression failure(s).")
        unavailable_total = sum(h_type_unavailable.values())
        if unavailable_total:
            breakdown = " | ".join(
                f"{layout}={count:,}"
                for layout, count in sorted(
                    ((layout, count) for layout, count in h_layout_counts.items() if layout != "common_header")
                )
            )
            print(
                f"NOTE: H type metadata unavailable from {unavailable_total:,} readable payload(s); "
                "hash evidence remains usable."
            )
            if breakdown:
                print(f"  Layouts: {breakdown}")
            if h_unavailable_with_exact_target_type:
                print(
                    f"  Exact target object filenames independently provide a type for "
                    f"{h_unavailable_with_exact_target_type:,} of those payload(s)."
                )

    print("[4/5] Correlating manifest flags with H/B/F membership and hash-confirmed evidence...")

    detail_csv = out_dir / "u43_manifest_info.csv"
    summary_csv = out_dir / "u43_flag_correlation.csv"
    bit_csv = out_dir / "u43_bit_correlation.csv"
    confirmed_csv = out_dir / "u43_hash_confirmed_flag_correlation.csv"
    package_csv = out_dir / "u43_hash_confirmed_package_correlation.csv"
    header_csv = out_dir / "u43_h_header_checks.csv"
    unavailable_csv = out_dir / "u43_h_type_unavailable.csv"
    cache_csv = out_dir / "u43_cache_validation.csv"
    summary_txt = out_dir / "u43_analysis_summary.txt"

    write_cache_validation(cache_csv, cache_rows)

    correlation = Counter()
    bit_corr = Counter()
    confirmed_correlation = Counter()
    confirmed_package_corr = Counter()
    nibble_totals = Counter()
    matched = 0
    unmatched = 0
    h_match_assets = 0
    h_mismatch_assets = 0
    h_read_error_assets = 0

    with detail_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "manifest",
                "manifest_version",
                "namespace",
                "section",
                "path",
                "hash_b64",
                "info_hex",
                "cdn_size",
                "upper_nibble_hex",
                "bit28",
                "bit29",
                "bit30",
                "bit31",
                "base_H",
                "base_B",
                "base_F",
                "base_membership",
                "base_H_packages",
                "base_B_packages",
                "base_F_packages",
                "h_target_hash_status",
                "base_H_hashes",
                "base_H_type_ids",
                "base_H_cache_files",
            ]
        )
        for manifest, namespace, section, path, manifest_hash, info, version in assets:
            key = (namespace, path)
            splits = memberships.get(key, set())
            label = membership_label(splits)
            nibble = (info >> 28) & 0xF
            bits = tuple((info >> bit) & 1 for bit in range(28, 32))
            nibble_totals[nibble] += 1
            correlation[(nibble, label)] += 1
            for bit_no, value in zip(range(28, 32), bits):
                bit_corr[(bit_no, value, label)] += 1
            if splits:
                matched += 1
            else:
                unmatched += 1

            h_status, h_hashes, h_types, h_caches = summarize_h_status(
                h_results.get(key, []), manifest_hash, repair
            )
            if args.skip_h_cache_read and "H" in splits:
                h_status = "skipped"
            if h_status == "match":
                h_match_assets += 1
                confirmed_correlation[(nibble, label)] += 1
                for split in "HBF":
                    for package in sorted(packages_by_key.get(key, {}).get(split, set())):
                        confirmed_package_corr[(nibble, split, package)] += 1
            elif h_status == "mismatch":
                h_mismatch_assets += 1
            elif h_status == "read_error":
                h_read_error_assets += 1

            writer.writerow(
                [
                    manifest,
                    version,
                    namespace,
                    section,
                    path,
                    repair.b64m_encode(manifest_hash),
                    f"0x{info:08X}",
                    info & repair.MANIFEST_INFO_SIZE_MASK,
                    f"0x{nibble:X}",
                    *bits,
                    int("H" in splits),
                    int("B" in splits),
                    int("F" in splits),
                    label,
                    ";".join(sorted(packages_by_key.get(key, {}).get("H", set()))),
                    ";".join(sorted(packages_by_key.get(key, {}).get("B", set()))),
                    ";".join(sorted(packages_by_key.get(key, {}).get("F", set()))),
                    h_status,
                    h_hashes,
                    h_types,
                    h_caches,
                ]
            )

    with header_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "namespace",
                "path",
                "cache",
                "package",
                "offset",
                "compressed_len",
                "length",
                "base_hash_b64",
                "type_id",
                "type_layout",
                "type_parse_reason",
                "target_sections",
                "target_upper_nibbles",
                "target_observed_type_ids",
                "read_ok",
                "hash_matches_any_u43_target",
                "error",
            ]
        )
        for (namespace, path), rows in sorted(h_results.items()):
            for row in rows:
                writer.writerow(
                    [
                        namespace,
                        path,
                        row["cache"],
                        row["package"],
                        row["offset"],
                        row["compressed_len"],
                        row["length"],
                        row["hash_b64"],
                        row["type_id"],
                        row["type_layout"],
                        row["type_parse_reason"],
                        row["target_sections"],
                        row["target_upper_nibbles"],
                        row["target_observed_type_ids"],
                        int(row["read_ok"]),
                        int(row["hash_matches_any_target"]),
                        row["error"],
                    ]
                )

    with unavailable_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["layout", "cache", "reason", "count"])
        for (layout, cache_name, reason), count in sorted(
            h_type_unavailable.items(),
            key=lambda item: (item[0][0], item[0][1], item[0][2]),
        ):
            writer.writerow([layout, cache_name, reason, count])

    with summary_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["upper_nibble_hex", "base_membership", "count"])
        for (nibble, label), count in sorted(correlation.items()):
            writer.writerow([f"0x{nibble:X}", label, count])

    with bit_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["bit", "value", "base_membership", "count"])
        for (bit_no, value, label), count in sorted(bit_corr.items()):
            writer.writerow([bit_no, value, label, count])

    with confirmed_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["upper_nibble_hex", "base_membership", "hash_confirmed_count"])
        for (nibble, label), count in sorted(confirmed_correlation.items()):
            writer.writerow([f"0x{nibble:X}", label, count])

    with package_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["upper_nibble_hex", "split", "base_package", "hash_confirmed_count"])
        for (nibble, split, package), count in sorted(confirmed_package_corr.items()):
            writer.writerow([f"0x{nibble:X}", split, package, count])

    with summary_txt.open("w", encoding="utf-8") as f:
        f.write("U43 manifest info / pre-U43 Cache.Windows correlation\n")
        f.write("===================================================\n\n")
        f.write(f"Root: {root}\n")
        f.write(f"Cache.Windows: {cache_dir}\n")
        f.write(f"Manifests: {len(manifests)}\n")
        f.write(f"Manifest entries: {len(assets)}\n")
        f.write(f"TOCs: {len(tocs)}\n")
        f.write("TOC versions: " + ", ".join(f"v{k}={v}" for k, v in sorted(toc_versions.items())) + "\n")
        f.write(f"Cache files missing: {len(missing_caches)}\n")
        f.write(f"TOC entries exceeding cache bounds: {bad_bounds}\n")
        f.write(f"Base unique H namespace+paths: {len(split_unique['H'])}\n")
        f.write(f"Base unique B namespace+paths: {len(split_unique['B'])}\n")
        f.write(f"Base unique F namespace+paths: {len(split_unique['F'])}\n")
        f.write(f"Manifest namespace+paths matched in pre-U43 TOCs: {matched}\n")
        f.write(f"Manifest namespace+paths not found in pre-U43 TOCs: {unmatched}\n")
        if args.skip_h_cache_read:
            f.write("H payload/hash check: skipped\n")
        else:
            f.write(f"Manifest entries with matching pre-U43 H hash: {h_match_assets}\n")
            f.write(f"Manifest entries with differing pre-U43 H hash: {h_mismatch_assets}\n")
            f.write(f"Manifest entries whose H payload could not be read: {h_read_error_assets}\n")
            f.write(f"H payload read/decompression failures: {sum(h_read_errors.values())}\n")
            f.write(f"H type metadata unavailable from readable payloads: {sum(h_type_unavailable.values())}\n")
            f.write(
                "H payload layouts: "
                + ", ".join(f"{layout}={count}" for layout, count in sorted(h_layout_counts.items()))
                + "\n"
            )
            f.write(
                "Type-unavailable H payloads with exact target-object type evidence: "
                f"{h_unavailable_with_exact_target_type}\n"
            )
        f.write("\nManifest raw high-nibble totals (bit 28 is size bit 28):\n")
        for nibble, count in sorted(nibble_totals.items()):
            f.write(f"  0x{nibble:X}: {count}\n")
        f.write("\nRaw high nibble vs base H/B/F membership (bit 28 includes size overflow):\n")
        for (nibble, label), count in sorted(correlation.items()):
            f.write(f"  0x{nibble:X}  {label:7s}  {count}\n")
        f.write("\nRaw high nibble vs base H/B/F membership (hash-confirmed; bit 28 includes size overflow):\n")
        for (nibble, label), count in sorted(confirmed_correlation.items()):
            f.write(f"  0x{nibble:X}  {label:7s}  {count}\n")
        f.write("\nPer-bit correlation (all path matches):\n")
        for (bit_no, value, label), count in sorted(bit_corr.items()):
            f.write(f"  bit{bit_no}={value}  {label:7s}  {count}\n")

    print("[5/5] Auditing size bit 28 / >256 MiB candidate(s)...")
    bit28_result = write_bit28_research(
        out_dir,
        root,
        assets,
        memberships,
        entries_by_key,
        packages_by_key,
        h_results,
        exact_target_types,
        repair,
        oodle,
        args.compare_manifest_dir,
    )
    print(
        f"  Candidates: {bit28_result['candidates']} | peer rows: {bit28_result['peer_rows']} | "
        f"payload samples: {bit28_result['payload_rows']} | CachePlan hits: {bit28_result['cacheplan_hits']}"
    )
    if args.compare_manifest_dir:
        print(f"  Cross-build candidate rows: {bit28_result['compare_rows']}")

    print()
    print("Done. Zip/send the entire output folder. It now contains:")
    for path in (
        summary_txt,
        summary_csv,
        bit_csv,
        confirmed_csv,
        package_csv,
        cache_csv,
        header_csv,
        unavailable_csv,
        detail_csv,
        *bit28_result["paths"],
    ):
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
