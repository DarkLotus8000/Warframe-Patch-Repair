# Warframe/OpenWF Update Patch Repair

Standalone repair script for incomplete Warframe update patches captured with **Ninja Capture Tool v1.0** for OpenWF/SpaceNinjaServer.

NCT v1.1 is intended to perform this repair internally. This standalone script remains useful for existing/archived NCT v1.0 captures, diagnostics, recovery, and format research.

The current implementation has been validated against **Warframe Update 44**, including U44.0.1 through U44.0.3. A future content update may change Packages.bin, B.Cache manifests, SHCC/Oodle framing, Cache.Windows, or Warframe.x64.exe type registration. Unsupported formats should be validated before parser support is widened.

For the detailed format notes and maintenance rationale, see [`Warframe-Patch-Repair-Internals.md`](Warframe-Patch-Repair-Internals.md).

## Requirements

Python 3.11+ is recommended.

```text
py -m pip install -r requirements.txt
```

`pycurl` provides the libcurl network transport used for official H.Cache/B.Cache and asset CDN downloads. Each download worker reuses one thread-local libcurl easy handle so compatible HTTP connections can remain persistent across many assets instead of reconnecting for every object. `pefile` and `capstone` are optional at runtime but recommended for matching `Warframe.x64.exe` type extraction. `google-crc32c` is used when its native C extension is available, giving CRC32C hardware/native acceleration; if that extension cannot be loaded, the repairer automatically keeps its built-in table-based Python CRC32C fallback. The release bundle also contains the pinned `oo2core_9.dll` used for Oodle decompression.

## Normal repair

```text
py warframe_patch_repair.py <update-patch-root> <original-base-root>
```

Example:

```text
py warframe_patch_repair.py "D:\GitHub\U44.0.x\44.0.2" "D:\Warframe\U44-Steam-Base"
```

The base must be the original, unupdated Steam base used for the update capture, or its `Cache.Windows` directory. Normal repair modifies the supplied patch in place.

Before parsing the target B.Cache set, the repairer also tries to establish complete manifest coverage from `H.Cache.bin`. A captured matching H.Cache is preferred; otherwise the official DE sentinel H.Cache is fetched for the observed manifest type. Both captured/local and official H.Cache inputs are capped at 16 MiB before decoding. An official H.Cache is trusted only when every already-captured B.Cache hash agrees with it. If it matches, any missing B.Cache families are downloaded by their exact H.Cache target hashes before normal repair continues. A valid captured H.Cache can also bootstrap a capture that contains no B.Cache manifests at all. If manifest coverage cannot be verified, the script may continue best-effort but the final status is incomplete/non-zero rather than `Repair completed successfully.`

## Arguments

| Argument | Description |
| --- | --- |
| `root` | Warframe/update-patch root. Defaults to the current directory if omitted. |
| `base` | Original unupdated Steam-base root or `Cache.Windows` directory. Required for normal repair. |
| `-h`, `--help` | Show command-line help and exit. |
| `-t`, `--patch-types-only` | Diagnostic FontCache-only repair without base comparison. |
| `-l`, `--openwf-log <path>` | Exact current-session OpenWF trace used only as a final type fallback. |
| `-n`, `--no-stripped` | Repair service + packed sections while excluding stripped entries. |
| `-s`, `--only-stripped` | Export only changed/new stripped-section assets to a separate OpenWF/Content tree. H.Cache/B.Cache completion is staged temporarily so the source patch is not modified. |
| `-o`, `--stripped-output <path>` | With `--only-stripped`, use this exact new output directory. |
| `-w <N>`, `--download-workers <N>` | Parallel manifest CDN asset downloads. Defaults to **2**; use `1` for sequential downloading/debugging. Accepted range: 1-16. |

### Argument rules

- `--patch-types-only` cannot be combined with a base path or manifest section filters.
- `--no-stripped` and `--only-stripped` are mutually exclusive.
- `--stripped-output` requires `--only-stripped`, and the destination must not already exist.
- `-w` / `--download-workers` accepts 1-16. The default is 2, matching the official PC updater's aggressive two-fetch-worker behavior observed during reverse engineering. Each worker can hold one complete CDN object in memory while it is verified/saved, so very high worker counts trade additional memory for possible throughput and are mainly intended for experiments/debugging.
- Long-option abbreviation is disabled; standard `argparse` short-option behavior is otherwise retained.

## Examples

```text
py warframe_patch_repair.py <patch> <base> --no-stripped
py warframe_patch_repair.py <patch> <base> --only-stripped
py warframe_patch_repair.py <patch> <base> -s -o "D:\Exports\U44-stripped"
py warframe_patch_repair.py <patch> <base> -l "D:\OpenWF\trace.log"
py warframe_patch_repair.py <patch> <base> -w 1
py warframe_patch_repair.py <patch> <base> -w 4
py warframe_patch_repair.py <patch> --patch-types-only
```

## Important behavior

- `H.Cache.bin` is used as the meta-manifest for B.Cache coverage. Matching is proven against every captured B.Cache hash before missing manifest families are recovered; a valid captured H.Cache can bootstrap the family set when no B.Cache manifests were captured. Captured/local and official H.Cache inputs share the same 16 MiB size limit.
- The complete target B.Cache set is then the authoritative target path/hash inventory. The family set is derived from H.Cache rather than hard-coding the 19 families observed in U44. Unverified coverage makes the run incomplete even if every discovered asset otherwise succeeds.
- Manifest version **14** is the only accepted format. It was directly verified across all **38/38** supplied U44.0.1/U44.0.2 manifests, including the large decoder-type-12 families.
- Manifest discovery accepts unsuffixed Windows/DX manifests and `B.Cache.Windows_<ASCII-alphanumeric-token>.bin`; DX11/DX12 suffixes and malformed Windows suffixes are rejected. Missing DX11 and DX12 manifests are recovered independently from verified H.Cache metadata, and their `Content/9` / `Content/A` type evidence remains isolated.
- The owning manifest determines the CDN namespace. Language-looking filenames do not override it; `_xx` is an observed U44 family and maps to `Content/0_xx`. U44.0.1/U44.0.2 do not expose a separate `B.Cache.LanguageVO` family: dialog/audio assets are carried by the existing Windows language/variant manifests, so an `_en.wav` owned by `B.Cache.Windows_zh` remains in `Content/0_zh`.
- Decoded manifest payloads and Oodle SHCC chunk payloads require exact consumption; unexplained trailing bytes are rejected.
- Packages.bin version **46** is the only accepted Packages layout.
- Packages ambiguity is decided before format parsing. Multiple integrity-valid Packages objects stop the run instead of selecting a stale supported one.
- A single integrity-valid unsupported/changed Packages layout is fatal.
- Missing or integrity-broken Packages metadata remains non-fatal because other type evidence can still complete a repair.
- Existing/downloaded objects must pass exact container/hash verification. CRC32C uses the native `google-crc32c` C backend when it is actually available; otherwise the built-in Python implementation remains the compatibility fallback.
- Manifest entry `info` metadata is retained. For the evidenced U43/U44 layout, the low 28 bits are the exact CDN object size; this is validated by real objects above the old 24-bit/16 MiB boundary. The upper nibble remains separate metadata and is not required for download-size planning.
- Before asset downloads begin, the repairer checks which selected objects are already valid/copyable and prints the remaining manifest CDN file count and total byte size. Final non-mutating preflight outcomes such as already-valid local objects and unresolved types are cached for the result pass, avoiding an immediate duplicate validation read. Manifest CDN transfers use **2 bounded workers by default** (`-w 1` restores sequential behavior). PyCURL/libcurl keeps one reusable easy handle per worker thread; the old forced `Connection: close` behavior is gone, allowing libcurl to reuse compatible persistent connections across successive assets. Each finished asset is printed permanently above the one transient bottom `[Download]` row; that row is immediately restored after completion/retry/warning messages and reports combined progress, smoothed speed and ETA. Per-file verification/saving rows are suppressed while the aggregate row owns the console. Native Oodle decompression is serialized behind the concurrent network transfers rather than assuming undocumented thread-safety for the shared DLL handle. Verified response-size mismatches adjust the running total instead of silently corrupting progress. Direct OpenWF-404 fallback objects remain outside that manifest-derived total.
- Type/metadata ambiguity is not guessed away. Same-path type evidence can cross `Content/0*` language namespaces only when all observed types agree; conflicting language-family evidence stays unresolved.
- Writes are atomic; low/full-disk handling preserves a 64 MiB reserve.
- Parsed manifest summaries show the observed version, for example `v14`, alongside service/packed/stripped counts.
- Run-mode combinations, the supplied Steam base/`Cache.Windows` (including the presence of at least one usable regular `H.<package>.toc` file), and an explicit OpenWF log are validated before H.Cache/B.Cache completion can modify the patch. `run()` enforces the same mode contract as the CLI for direct callers.
- Unverified B.Cache coverage, unresolved types, unknown base classification, and parse/download failures make the run incomplete and return a non-zero status. Ctrl+C returns 130.

## Tests

From the project root:

```text
py -B -m unittest discover -s tests -v
```

From inside the `tests` directory:

```text
py -B -m unittest discover -s . -v
```

Or run the file directly from `tests`:

```text
py -B test_warframe_patch_repair.py -v
```

The focused suite contains **72 tests** covering H.Cache parsing/self-hash validation, missing-manifest completion including independent DX11/DX12 recovery, captured-H.Cache-only bootstrap, fail-closed/unverified coverage status, end-to-end non-destructive stripped-manifest staging, bounded captured/official H.Cache inputs, fail-fast run/base/OpenWF-log validation, latest-session OpenWF 404 scoping, B.Cache-over-H.Cache content-root precedence, Packages compatibility boundaries, manifest v14, real U44 language-manifest structure and 28-bit CDN-size metadata, `_de`/`_xx` namespace ownership, VO-style language-manifest ownership, cross-language same-path type resolution with ambiguity rejection, DX11/DX12 type-evidence isolation and base-package namespace mapping, strict manifest filename grammar and duplicate-family rejection, direct and outer-`0x43` SHCC CRC/hash validation, Oodle trailing-payload rejection, strict LZF failure handling, raw framed Cache.Windows blocks, manifest CDN planning/global progress retry accounting, pinned-bottom aggregate progress with live finished-asset rows, preflight-result reuse, shared manifest type-fallback resolution, configurable two-worker concurrency/sequential fallback including the `-w` alias, libcurl connection-handle reuse, redirect-body isolation and transient-HTTP retry behavior, transient-line cursor restoration after stale-tail erasure, native/google CRC32C selection with Python fallback, atomic-write/disk-full retry safety, optional EXE-extractor failure normalization, and filesystem-enumeration diagnostics.

The `-B` flag prevents the test runs themselves from creating `.pyc`/`__pycache__` files. The test harness also suppresses transient repair-progress output so verbose `unittest` rows remain readable; on Windows it enables console VT processing up front so Python 3.14 can retain its normal colored `ok`/`OK` output without depending on repair progress as a side effect. `.gitignore` still excludes Python cache/test-environment artifacts from Git, while `.gitattributes` keeps source/docs on LF and marks bundled binaries as binary.

## Future-build note

If U45+ changes manifest version 14, Packages version 46, SHCC/Oodle framing, Cache.Windows, or Warframe.x64.exe registration patterns, validate the new real format first. Do not widen version checks merely to make a new build run.

