# Warframe/OpenWF Update Patch Repair

Standalone repair utility for incomplete Warframe update patches captured with **Ninja Capture Tool v1.0** for OpenWF/SpaceNinjaServer.

NCT v1.1 is intended to perform this repair internally. This standalone tool remains useful for existing/archived NCT v1.0 captures, diagnostics, recovery, and format research.

The current implementation has been validated against **Warframe Update 44**, including U44.0.1 and U44.0.2. A future content update may change Packages.bin, B.Cache manifests, SHCC/Oodle framing, Cache.Windows, or Warframe.x64.exe type registration. Unsupported formats should be validated before parser support is widened.

For the detailed format notes and maintenance rationale, see [`Warframe-Patch-Repair-Internals.md`](Warframe-Patch-Repair-Internals.md).

## Requirements

Python 3.11+ is recommended.

```text
py -m pip install -r requirements.txt
```

`pefile` and `capstone` are optional at runtime but recommended for matching `Warframe.x64.exe` type extraction. The release bundle also contains the pinned `oo2core_9.dll` used for Oodle decompression.

## Normal repair

```text
py warframe_patch_repair.py <update-patch-root> <original-base-root>
```

Example:

```text
py warframe_patch_repair.py "D:\GitHub\U44.0.x\44.0.2" "D:\Warframe\U44-Steam-Base"
```

The base must be the original, unupdated Steam base used for the update capture, or its `Cache.Windows` directory. Normal repair modifies the supplied patch in place.

## Arguments

| Argument | Description |
| --- | --- |
| `root` | Warframe/update-patch root. Defaults to the current directory if omitted. |
| `base` | Original unupdated Steam-base root or `Cache.Windows` directory. Required for normal repair. |
| `-h`, `--help` | Show command-line help and exit. |
| `-t`, `--patch-types-only` | Diagnostic FontCache-only repair without base comparison. |
| `-l`, `--openwf-log <path>` | Exact current-session OpenWF trace used only as a final type fallback. |
| `-n`, `--no-stripped` | Repair service + packed sections while excluding stripped entries. |
| `-s`, `--only-stripped` | Export only changed/new stripped-section assets to a separate OpenWF/Content tree. |
| `-o`, `--stripped-output <path>` | With `--only-stripped`, use this exact new output directory. |

### Argument rules

- `--patch-types-only` cannot be combined with a base path or manifest section filters.
- `--no-stripped` and `--only-stripped` are mutually exclusive.
- `--stripped-output` requires `--only-stripped`, and the destination must not already exist.
- Long-option abbreviation is disabled; standard `argparse` short-option behavior is otherwise retained.

## Examples

```text
py warframe_patch_repair.py <patch> <base> --no-stripped
py warframe_patch_repair.py <patch> <base> --only-stripped
py warframe_patch_repair.py <patch> <base> -s -o "D:\Exports\U44-stripped"
py warframe_patch_repair.py <patch> <base> -l "D:\OpenWF\trace.log"
py warframe_patch_repair.py <patch> --patch-types-only
```

## Important behavior

- Target B.Cache manifests are authoritative target path/hash inventories.
- Manifest version **14** is the only accepted format. It was directly verified across all **38/38** supplied U44.0.1/U44.0.2 manifests, including the large decoder-type-12 families.
- Manifest discovery accepts unsuffixed Windows/DX manifests and `B.Cache.Windows_<ASCII-alphanumeric-token>.bin`; DX11/DX12 suffixes and malformed Windows suffixes are rejected.
- The owning manifest determines the CDN namespace. Language-looking filenames do not override it; `_xx` is an observed U44 family and maps to `Content/0_xx`.
- Decoded manifest payloads and Oodle SHCC chunk payloads require exact consumption; unexplained trailing bytes are rejected.
- Packages.bin version **46** is the only accepted Packages layout.
- Packages ambiguity is decided before format parsing. Multiple integrity-valid Packages objects stop the run instead of selecting a stale supported one.
- A single integrity-valid unsupported/changed Packages layout is fatal.
- Missing or integrity-broken Packages metadata remains non-fatal because other type evidence can still complete a repair.
- Existing/downloaded objects must pass exact container/hash verification.
- Type/metadata ambiguity is not guessed away.
- Writes are atomic; low/full-disk handling preserves a 64 MiB reserve.
- Parsed manifest summaries show the observed version, for example `v14`, alongside service/packed/stripped counts.
- Unresolved types, unknown base classification, parse/download failures make the run incomplete and return a non-zero status. Ctrl+C returns 130.

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

The focused suite covers Packages compatibility boundaries, manifest v14 and real U44 language-manifest structure, `_de`/`_xx` namespace ownership, strict manifest filename grammar and duplicate-family rejection, direct and outer-`0x43` SHCC CRC/hash validation, Oodle trailing-payload rejection, optional EXE-extractor failure normalization, and filesystem-enumeration diagnostics.

The `-B` flag prevents the test runs themselves from creating `.pyc`/`__pycache__` files. The test harness also suppresses transient repair-progress output so verbose `unittest` rows remain readable; on Windows it enables console VT processing up front so Python 3.14 can retain its normal colored `ok`/`OK` output without depending on repair progress as a side effect. `.gitignore` still excludes Python cache/test-environment artifacts from Git, while `.gitattributes` keeps source/docs on LF and marks bundled binaries as binary.

## Future-build note

If U45+ changes manifest version 14, Packages version 46, SHCC/Oodle framing, Cache.Windows, or Warframe.x64.exe registration patterns, validate the new real format first. Do not widen version checks merely to make a new build run.

## ZIP contents

```text
warframe_patch_repair.py
tests/test_warframe_patch_repair.py
oo2core_9.dll
requirements.txt
README.md
Warframe-Patch-Repair-Internals.md
.gitignore
.gitattributes
```
