# Warframe/OpenWF Update Patch Repair Internals

## Maintainer and reverse-engineering guide

This document explains how `warframe_patch_repair.py` works, what information it trusts,
which parts are based on observed Warframe Update 44 data, why several seemingly simpler
approaches were deliberately rejected, and what must be revalidated when Warframe changes.

It is intentionally much more detailed than the normal README. The intended readers are:

- future human maintainers;
- AI/code assistants working on the repairer;
- OpenWF/Ninja Capture Tool contributors;
- preservation researchers investigating Warframe cache/CDN formats;
- anyone debugging a future build where the current assumptions stop matching reality.

The most important maintenance rule is this:

> **Do not convert an observation from one Warframe build into a permanent format rule
> unless real files from later builds prove that rule still holds.**

The current implementation was validated primarily against Update 44, especially U44.0.1
through U44.0.3. U45 may preserve every relevant structure, change only one small field, or
change several independent layers at once. Treat the first U45 repair as a format-validation
exercise rather than merely another test run.

---

# 1. What problem this repair script solves

Ninja Capture Tool can capture Warframe CDN objects used while updating/starting the
game. The original standalone repair workflow was validated against v1.0-era captures. A
capture can still be incomplete even when it looks large or the launcher update itself finished
successfully. A later OpenWF client run may request objects that were not
captured during the original update session.

The repairer tries to reconstruct the **set of CDN objects that belong in the update patch**
without blindly downloading everything listed by the target build.

That distinction matters because a target installation contains both:

1. content already present in the original Steam base; and
2. content changed or newly introduced by the launcher update.

An update patch should normally contain category 2, not a complete duplicate of category 1.

The repairer therefore combines multiple independent sources of information:

- target `B.Cache.*` manifest objects;
- original-base `Cache.Windows` H TOCs/CommonHeaders;
- objects already captured in `OpenWF/Content`;
- a captured `Packages.bin` object;
- the matching target `Warframe.x64.exe`;
- optionally, exact current-session OpenWF 404 requests.

No one source is sufficient in every case.

---

# 2. Mental model: four different worlds

A recurring source of confusion is treating several Warframe storage representations as if
they were interchangeable. They are not.

## 2.1 The original Steam base

This is the unupdated installation associated with the Steam depot manifest used as the base
for the capture/update.

For the repairer, the important part is:

```text
<base>/Cache.Windows/
    H.*.toc
    H.*.cache
    ...
```

The base is used to answer one question:

> Did this logical target asset already exist with the exact same manifest hash before the
> update?

It is also a secondary source of same-path type hints.

The repairer does **not** turn the base's cache files directly into OpenWF CDN objects.

## 2.2 The target/update patch

This is the NCT/OpenWF capture being repaired. A common shape is:

```text
<patch>/
    Warframe.x64.exe              # optional but strongly useful
    OpenWF/
        Content/
            0/
            0_de/
            0_en/
            9/
            A/
            ...
```

The script accepts several bounded roots and searches these layouts explicitly:

```text
<root>/OpenWF/Content
<root>/OpenWF
<root>/Content
<root>
```

It does not recursively search arbitrary descendants. A recursively guessed root can select
an old or unrelated patch directory and silently corrupt the evidence model. Across the bounded
layouts above, a root containing `B.Cache.*` manifests is preferred over an earlier root that
contains only `H.Cache.bin`; H.Cache-only evidence is used only when no supported root contains
B.Cache manifests.

## 2.3 The target installation

The target installation is what exists after the launcher applied the update. Its logical
asset state is represented by the target manifests.

The standalone repairer does not require a complete target `Cache.Windows` directory. This
is important because an NCT update patch is not itself a full installed game.

## 2.4 The CDN/OpenWF object namespace

OpenWF stores CDN objects using names that encode:

- namespace;
- logical path;
- numeric type ID;
- modified-base64 target hash.

Conceptually:

```text
<namespace><logical-path>!<TYPE>_<HASH>
```

Examples observed during U44 work include forms such as:

```text
0/Lotus/.../Transmission.lua!78_<hash>
0/Lotus/.../SomeSound.wav!8B_<hash>
9/Lotus/.../Shader.hlsl!<type>_<hash>
A/Lotus/.../Shader.hlsl!<type>_<hash>
```

The exact numeric type is build/data dependent and must not be inferred from these examples.

---

# 3. CDN object naming and modified base64

The 16-byte target digest embedded in a manifest/CommonHeader is encoded into the object name
using the game's modified base64 convention:

```python
base64.b64encode(data)
    .decode("ascii")
    .rstrip("=")
    .replace("/", "-")
```

The repairer calls this representation `b64m`.

The slash replacement matters because the hash is embedded in a URL/path-like object name.
The `+` character is left in the logical object name, but URL construction percent-encodes it
rather than allowing it to be interpreted as a space.

The numeric type ID appears in uppercase hexadecimal when the repairer generates a name:

```text
namespace + logical_path + "!" + TYPE_HEX + "_" + b64m_hash
```

The type is **not part of the 16-byte manifest hash**. It is separate metadata required to
construct the exact CDN object path.

This separation is the central reason the repair problem is difficult: the target manifests
can tell us the path and hash while still leaving us without the type number.

---

# 4. Namespaces: normal, language, DX11 and DX12

The repairer currently recognizes these target manifest families:

| Manifest family | OpenWF/CDN namespace |
|---|---|
| `B.Cache.Windows.bin` | `0` |
| `B.Cache.Windows_<language>.bin` | `0_<language>` |
| `B.Cache.Dx11.bin` | `9` |
| `B.Cache.Dx12.bin` | `A` |

Examples:

```text
B.Cache.Windows_de.bin -> Content/0_de
B.Cache.Windows_en.bin -> Content/0_en
B.Cache.Windows_xx.bin -> Content/0_xx
B.Cache.Dx11.bin       -> Content/9
B.Cache.Dx12.bin       -> Content/A
```

## 4.1 Observed U44 language/variant families

The U44.0.1 and U44.0.2 captures each contain the same 16 suffixed Windows manifest
families:

```text
de en es fr it ja ko pl pt ru tc th tr uk xx zh
```

Together with unsuffixed `B.Cache.Windows.bin`, `B.Cache.Dx11.bin` and
`B.Cache.Dx12.bin`, that makes 19 observed target manifest families in each capture.

The suffix is deliberately treated as an opaque namespace token rather than being checked
against a hard-coded language list. In particular, `_xx` is a real observed U44 family and
maps to `Content/0_xx`. This document does not assign a semantic meaning to `xx`; the
important repair behavior is to preserve the manifest family exactly instead of dropping or
renaming it because it does not look like an ordinary user-facing language code. The captured
`B.Cache.Windows_xx.bin` object is also byte-for-byte identical between the supplied U44.0.1
and U44.0.2 samples, illustrating that a hotfix does not necessarily replace every manifest
family.

Manifest discovery intentionally accepts `B.Cache.Windows.bin` and
`B.Cache.Windows_<ASCII-alphanumeric-token>.bin` without hard-coding the observed U44 tokens.
DX manifests are intentionally unsuffixed: only `B.Cache.Dx11.bin` and `B.Cache.Dx12.bin` are
accepted. This prevents malformed names such as `Windows__xx` or `Dx11_de` from being treated
as separate manifest identities that later collapse into the same CDN namespace.

## 4.2 Why language is not inferred from filenames

A filename can contain apparent language markers, but that is not authoritative enough to
select a namespace.

For example, something named like:

```text
F_en_sdf.png
```

must not automatically be treated as `Content/0_en` merely because `_en` occurs in the name.

The namespace comes from the manifest/cache family that owns the entry. This avoids crossing
language families when two logical paths or filename patterns resemble one another.

## 4.3 Namespace groups used by type learning

For some type-learning operations, namespaces are grouped so related Windows language
namespaces can share appropriate evidence while shader families remain isolated.

The important design constraint is that DX11 and DX12 are not allowed to collide with each
other or with ordinary `Content/0` evidence.

A type learned from a DX11 shader object must not become a generic answer for a DX12 shader
with the same suffix.

## 4.4 Voiceover language behavior

The supplied U44.0.1/U44.0.2 target sets do not contain a separate `B.Cache.LanguageVO` or
`B.Cache.VO*` family. Voice/dialog content is carried by the existing Windows language/variant
manifests. In particular, the retained `Windows_en` and `Windows_zh` manifests contain dialog/audio
paths, and manifest ownership remains authoritative even when a filename contains another language
marker. For example, an `_en.wav` entry owned by `B.Cache.Windows_zh` maps to `Content/0_zh`.

`LanguageVO` is therefore treated as launcher/runtime selection context, not as another manifest
namespace grammar. Do not hard-code the currently observed VO choices into repair logic; future
builds may add languages without changing the ownership rule.

---

# 5. Target B.Cache manifests

The target manifests are the repairer's authoritative inventory of target logical paths and
16-byte target hashes.

## 5.1 U44 structure currently parsed

For Update 44, the parser expects the SHCC-decoded manifest header to begin with:

```text
embedded object hash[16]
u32 version
```

followed by three sections in this exact order:

```text
service
packed
stripped
```

Each section begins with:

```text
u32 entry_count
```

Each entry is parsed as:

```text
u32 path_length
path[path_length]
manifest_hash[16]
u32 info
```

The `info` field is retained in `ManifestAsset`. Current U43/U44 evidence establishes:

```text
bits  0..27  -> exact CDN object size in bytes
bits 28..31  -> separate per-entry metadata
```

The 28-bit size boundary is evidence-backed rather than inferred from small files. A real U44
`Packages.bin` CDN object is 22,081,406 bytes and carries `info = 0x2150EF7E`; masking with
`0x0FFFFFFF` yields exactly 22,081,406. An independent U43 `Packages.bin` above 16 MiB follows
the same layout. The earlier 24-bit-size/high-8-bit-flags interpretation was therefore incomplete.

The upper nibble is preserved but is not required for repair/download-size correctness. Research
evidence strongly associates three of those bits with H/B/F cache participation, while bit 28
remains intentionally unnamed until matching-build evidence proves its meaning. Do not make the
download planner depend on that unresolved flag.

Before asset downloading, the repairer preflights selected manifest candidates using the same
local-object/type evidence rules needed to decide whether a CDN fetch is actually necessary. It
sums `info & 0x0FFFFFFF` only for objects that still need the CDN. Final non-mutating preflight
outcomes (for example, an already-valid local object or an unresolved type) are cached and reused
by the result pass so the same local bytes are not immediately read and verified again. Cases that
still require a copy, repair, or write are deliberately not cached as final results. The resulting
manifest download list is then fetched through a bounded `ThreadPoolExecutor`; the default is two
workers, matching the official PC updater's observed aggressive fetch pool. `-w 1` /
`--download-workers 1` preserves the old sequential transport path, while values up to 16 are
accepted for controlled experiments. Each worker may hold one complete CDN response in memory
until verification and atomic saving finish, so increasing the worker count also increases peak
memory pressure; 2 remains the compatibility-oriented default.

`OverallDownloadProgress` is shared by the workers and keeps separate provisional byte counts per
thread. One global row reports committed + active bytes, smoothed aggregate wire speed, ETA and
completed-file count. The worker count is already printed once by the download plan, so the
transient row deliberately does not append changing active-worker counts or filenames; this keeps
the status width steadier and avoids duplicating information. The row stays transient at the bottom
of the console: whenever an asset finishes, its permanent result line is printed above it and the
aggregate row is immediately redrawn below. Retry/warning messages use the same locked message
scope. Planned download results are therefore visible live and are not printed a second time during
the later result-accounting pass. Per-file verification and saving rows are suppressed while this
aggregate row is active so concurrent workers cannot fight for the same terminal line. Retry
attempts remove only that worker's provisional completion so another active transfer is not
disturbed. Native Oodle decompression is serialized with a small
lock while network I/O remains concurrent; this avoids assuming undocumented thread-safety for the
one shared DLL handle. A verified response whose real size differs from manifest metadata adjusts
the running total and emits a warning rather than hiding the discrepancy. Direct OpenWF-404
fallback objects are not part of this manifest-derived total because they do not carry manifest
`info` metadata.

The parser reads the `u32 version` field explicitly and accepts only:

```text
version 14
```

That value is evidence-backed rather than guessed. All **38/38** supplied U44.0.1/U44.0.2
`B.Cache.*` manifests were directly decompressed and inspected, including the six large
decoder-type-12 families in both builds. Every one used manifest version 14, and every decoded
manifest payload was consumed exactly by the service/packed/stripped parser with zero trailing
bytes.

`UnsupportedManifestVersionError` is therefore a compatibility boundary. A future version such
as 15 must stop the repair before entry interpretation rather than being counted as one ordinary
manifest parse failure and ignored. Likewise, unexplained trailing bytes are rejected even when
they are zero: exact payload consumption is part of the observed U44 layout.

## 5.2 Why the section name is retained

The section is retained because CLI behavior depends on it:

- default: service + packed + stripped;
- `--no-stripped`: service + packed only;
- `--only-stripped`: stripped only.

The final report also breaks results down by section.

## 5.3 Duplicate entries

Manifest objects are deduplicated by:

```text
(namespace, logical_path, manifest_hash)
```

A duplicate occurrence is not automatically an error because the same target object can be
referenced more than once.

## 5.4 Multiple manifests for one family are different

The script refuses to continue if the capture contains more than one target manifest for the
same cache family/language.

For example, two different captured `B.Cache.Windows.bin!TYPE_HASH` objects would make it
unclear which target build is being repaired.

The repairer does **not** merge them and does **not** choose the newest filesystem timestamp.
That would turn stale capture debris into silent target-build selection.

## 5.5 H.Cache meta-manifest completion

`H.Cache.bin` sits one level above the B.Cache manifests. Its decoded header uses a 20-byte
prefix followed by grouped path/hash records. The repairer structurally parses that table and
selects only supported B.Cache paths; it does not hard-code the 19 families observed in U44.

The official sentinel object is requested using the manifest type already observed on the
captured B.Cache files. For U44 that is type `E`, producing:

```text
https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w
```

Older target builds can therefore use their observed manifest type instead of forcing `E`. A
captured/local H.Cache object is preferred when available. The official DE object is used only
when the local copy is missing, unreadable, or does not match the captured target evidence. Both
captured/local and official H.Cache inputs are capped at 16 MiB before decoding. Official responses
check both Content-Length and actual streamed bytes; local files are size-checked and read through the
same fixed upper bound. This prevents a broken or unexpected input from consuming unbounded memory
before verification.

The sentinel filename deliberately does not carry H.Cache's real object hash. The repairer
therefore verifies its SHCC CRC32C and recomputes the embedded H-only object hash from the
decoded header payload before trusting the table.

Version matching is conservative. Every B.Cache manifest already present in the capture must:

1. exist in H.Cache under the same logical path; and
2. have exactly the same 16-byte target hash as the captured `B.Cache.*!TYPE_HASH` filename.

If any overlapping manifest disagrees, the H.Cache candidate is treated as another build and
no missing B.Cache files are downloaded from it. When all overlaps match, H.Cache becomes the
authoritative family inventory for that target and the repairer downloads each missing B.Cache
object by its exact H.Cache hash before parsing target assets.

The `/B.Cache.Windows.bin` entry is also the cache-manifest/build hash used by OpenWF. Printing
that value is useful diagnostics, but the repairer does not rely on that single entry alone when
other captured B.Cache hashes are available; all overlaps must agree.

This design fixes an important passive-capture limitation: the launcher can request individual
`0_<language>` assets without re-requesting that language's B.Cache manifest during the same
NCT session. H.Cache allows the standalone repairer to recover those omitted manifests without
guessing a language list or silently mixing builds.

A valid captured H.Cache can also bootstrap a capture with **zero initial B.Cache manifests**.
In that case there is no overlap set to compare, so the script trusts only the captured/local
H.Cache after its SHCC CRC and embedded self-hash verify; it does not fetch a live official
H.Cache and guess that it belongs to an otherwise unidentified historical target. The captured
H.Cache then supplies the complete B.Cache family inventory and exact target hashes.

If no H.Cache candidate can be verified, the script may continue best-effort with the B.Cache
manifests that are already present, but manifest coverage is explicitly marked `unverified`.
An unverified coverage state is included in the final incomplete reasons and forces a non-zero
exit status. This prevents a partial 14-of-19-style capture from ending with the misleading
`Repair completed successfully.` message merely because every discovered candidate succeeded.

---

# 6. SHCC containers and object verification

A correct URL is not enough. Every downloaded or existing object must verify against the
expected target hash before it is trusted.

## 6.1 Normal SHCC form

The normal SHCC preamble is:

```text
53 48 43 43 1F 00 00 00
"SHCC" ...
```

The first chunk after the preamble contains the logical header. The first 16 bytes of that
header are the digest compared with the target manifest hash.

The normal direct SHCC representation uses a footer marker:

```text
0x52
```

followed by a stored CRC32C. The repairer recomputes CRC32C over the container up to, but not
including, the final four-byte CRC field.

A direct SHCC object is accepted only if:

1. the SHCC preamble is valid;
2. the footer marker is `0x52`;
3. CRC32C matches;
4. the header chunk can be decoded;
5. the embedded 16-byte hash equals the exact expected hash.

CRC32C prefers the `google-crc32c` C extension when `google_crc32c.implementation == "c"`.
The native checksum is updated in 1 MiB chunks, so excluding the stored four-byte footer does not
require a second full-object copy. If the extension is absent or only its non-C implementation is
available, the repairer uses its existing table-based Python CRC32C path. This keeps old/offline
repair environments functional while allowing hardware/native acceleration in normal installs.

## 6.2 Observed U44 whole-object `0x43` wrapper

Real U44.0.2 samples exposed another representation, observed for at least B7 HDR and 8B WAV
objects.

These objects do not begin directly with the SHCC preamble. Instead, the complete SHCC object
is Oodle-compressed and ends with an outer wrapper footer containing:

```text
[... compressed inner SHCC ...]
raw_size (u32)
0x43
crc32c (u32)
```

The repairer validates this representation by:

1. checking the outer `0x43` marker;
2. verifying the outer CRC32C;
3. reading the advertised raw size;
4. Oodle-decompressing the complete inner object;
5. requiring the decompressed object to begin with the SHCC preamble;
6. decoding the SHCC header chunk;
7. comparing the embedded hash with the exact expected target hash.

### Important U44 lesson

The decompressed inner representation is **not required to contain another ordinary `0x52`
footer/CRC**.

Earlier reasoning assumed that the wrapper contained a complete ordinary SHCC object. Real
U44 samples showed that treating trailing inner payload bytes as a second footer causes valid
objects to be rejected.

Therefore the current rule is:

```text
normal direct SHCC:
    verify inner 0x52 CRC + target hash

0x43 whole-object wrapper:
    verify outer 0x43 CRC + successful SHCC unwrap + target hash
```

Do not change this back unless later samples prove a different representation.

## 6.3 SHCC chunk types currently handled

The header decoder currently handles:

```text
chunk type 0 -> uncompressed
chunk type 2 -> Oodle-compressed
```

Any other chunk type is rejected rather than guessed.

That is another future-build checkpoint.

---

# 7. Oodle runtime policy

The full repair bundle contains:

```text
oo2core_9.dll
```

next to the Python script.

The repairer intentionally:

- does not download Oodle at runtime;
- does not search a Warframe installation for a random Oodle DLL;
- does not search LocalAppData or the system path;
- verifies the bundled DLL's exact expected size;
- verifies its pinned SHA-256 before loading it.

Current pinned values in the source are:

```text
size:   582656 bytes
SHA256: 19452ae1abae65e1305d3818354d4fae7b1200294322f0d9c6d5ddeb7bd9f978
```

The reason is reproducibility. A decompression failure should not secretly mean that the
machine happened to load a different `oo2core_9.dll`.

The Oodle block parser also requires exact compressed-payload consumption. Once the expected
decompressed chunk size has been produced, any unexplained trailing bytes inside that SHCC
chunk are rejected. This is evidence-backed: the supplied U44.0.1/U44.0.2 B.Cache set covers
38 manifest objects and 370 observed Oodle blocks, and every block consumed its payload
exactly. A future build that adds framing after the final block should therefore fail clearly
instead of being silently accepted as U44-compatible.

---

# 8. Original-base Cache.Windows comparison

Normal repair needs the original unupdated Steam base because target manifests alone describe
the target state, not the delta from the base.

## 8.1 Why only H caches are needed

The repairer scans:

```text
H.*.toc
H.*.cache
```

The H entry/CommonHeader is sufficient for the information normal repair needs:

- target-comparable 16-byte hash;
- optional same-path type hint.

The standalone repairer does not reconstruct CDN objects from B/F cache payloads.

An earlier reconstruction direction was intentionally removed because the update patch does
not contain a target `Cache.Windows` tree from which a correct target CDN representation could
be synthesized. Downloading the exact CDN object and verifying it is safer.

## 8.2 TOC format accepted by the current code

The code requires:

```text
magic = 0x1867C64E
version in {16, 20}
```

Entries use the current struct:

```text
<qqiiii64s
```

Conceptually this includes:

- cache offset;
- timestamp;
- compressed length;
- decompressed length;
- reserved field;
- parent directory index;
- 64-byte name field.

`cache_offset == -1` means the entry defines a directory node.

`timestamp == 0` is skipped as a deleted/duplicate style TOC entry, matching the behavior the
repair work derived from LotusLib references.

## 8.3 Base namespace mapping from H package names

The cache package determines the namespace:

```text
...Dx11 -> 9
...Dx12 -> A
..._<2-3 letter language> -> 0_<language>
everything else -> 0
```

Examples include the normal H families and language-suffixed families such as
`H.Misc_en` / `H.Texture_en`.

This makes base comparison namespace-aware. The same logical path in `0_de` cannot satisfy a
`0_en` manifest entry.

## 8.4 Cache entry decompression

An entry can be:

- stored raw when compressed length equals decompressed length;
- framed into Warframe blocks;
- Oodle-compressed;
- decoded through the custom LZ/LZF-compatible fallback used by the cache reader.

For framed blocks, the current block header decoder expects the Warframe-style 8-byte header.

A critical observed rule is:

> If a framed block advertises equal compressed and decompressed sizes, treat the block as raw
> stored data rather than sending it into the LZF/Oodle decompression paths.

Without this distinction valid cache entries can fail decompression.

### LZF/LZ compatibility note

The repairer retains `lzf_decompress()` because existing Warframe cache tooling and community
documentation describe Cache.Windows data containing both Oodle and a custom LZ/LZF-style
encoding. The repairer therefore treats compression as a property of the individual block, not
as something inferred from a Warframe version or historical era.

Do **not** assign a historical cutoff to this branch from secondary documentation. Community
cache tools and notes describe Oodle and custom LZ/LZF-style blocks, but their historical
timelines are not treated as authoritative engine-history facts. The repairer therefore makes no
claim here about the exact Warframe update or year in which compression behavior changed.

Our U44 repair fixtures establish that the current base-cache reader works for the tested modern
repair cases and exercise raw/Oodle handling. They do **not** currently establish that U44 itself
requires the LZF fallback, nor do they establish when Warframe introduced, retired, or changed
its LZ encoding. Older Warframe cache formats changed more than once, so historical-version work
should be validated against real fixtures instead of assigning a format to a year or named update.

Keep the fallback while it remains small and compatible. It can be removed later only if real
fixtures for the supported version range show that it is unnecessary.

Reference context (community/research material, not authoritative format specifications):

- Puxtril/LotusLib cache/decompression notes:
  https://github.com/Puxtril/LotusLib
- PKBeam/Warframe-Game-File-Docs cache notes:
  https://github.com/PKBeam/Warframe-Game-File-Docs

## 8.5 CommonHeader information

The beginning of a decoded CommonHeader contains the 16-byte hash used for base comparison.

The parser then advances through:

```text
16-byte hash
u32 source_path_count
repeated source paths
u32 attribute_len
attribute bytes
optional attribute terminator
u32 type field
```

Only the low 16 bits of the type field are currently used as the CDN/cache type hint.

### Hash comparison is more fundamental than type parsing

A very important design decision is that a CommonHeader can still participate in base hash
comparison even if the later metadata layout cannot be parsed far enough to recover the type.

In other words:

```text
first 16 bytes readable -> hash evidence may still be valid
later type metadata unreadable -> lose the optional type hint only
```

This prevents a type-parser limitation from incorrectly converting a clearly unchanged or
changed asset into an unknown asset.

---

# 9. Changed / unchanged / new / unknown classification

For each selected target manifest object, normal repair compares the target hash with matching
base H entries for the same:

```text
(namespace, logical_path)
```

The classification rules are:

## 9.1 Unchanged

At least one readable matching base CommonHeader has the exact same 16-byte hash.

Result:

```text
unchanged
```

Normally the asset is not part of the update patch.

If the matching exact CommonHeaders also provide exactly one unambiguous type, that type can
be retained as a hint.

## 9.2 Changed

Readable base metadata exists for the same namespace/path, but none of its hashes equals the
target hash.

Result:

```text
changed
```

The target object becomes an update-patch candidate.

## 9.3 New

No base entry exists for the namespace/path, and there is no relevant namespace-level TOC
parse uncertainty.

Result:

```text
new
```

The target object becomes an update-patch candidate.

## 9.4 Unknown

The repairer cannot safely determine whether the target was already present in the base.

Examples:

- a relevant base cache entry exists but cannot be read/decompressed enough to obtain its
  16-byte hash;
- a relevant H TOC failed to parse, so absence from the partial index is not reliable.

Result:

```text
unknown
```

Unknown assets are not guessed. A full repair with unknown base assets is reported as
incomplete/non-zero.

This conservative behavior is intentional. Downloading an object because a broken base parser
made it *look* new would hide a format regression.

---

# 10. The FontCache exception

Normal delta logic alone was not enough in real client testing.

A repaired patch could pass the changed/new comparison and still produce runtime requests for
base-identical FontCache objects.

The important paths are under:

```text
/Temp/FontCache/
```

Real testing showed that the client can request these CDN objects during preprocessing even
when the target manifest hash equals the hash already present in the base.

Therefore normal repair deliberately does this:

```text
repair candidates
    = changed/new manifest assets
    + every manifest FontCache asset not already selected
```

This is not an accidental over-download. It is a compatibility exception derived from an
observed runtime failure.

A follow-up U44 validation run with no OpenWF log processed all manifest FontCache candidates
successfully, proving that this coverage can be driven statically rather than requiring 404s.

`--patch-types-only` exists mainly as a diagnostic way to exercise this FontCache path without
a base comparison. It is not the preferred normal repair workflow.

---

# 11. Why type resolution is the hardest part

A target manifest gives us:

```text
namespace
logical path
16-byte target hash
section
```

But a CDN/OpenWF object name also requires:

```text
numeric type ID
```

That type is not safely derivable from a generic extension table baked into the repair script.
Warframe types can be native classes, extension-based mappings, platform-dependent mappings,
or mappings that change with the executable/build.

The current design therefore uses an evidence hierarchy rather than a static snapshot.

---

# 12. Type-resolution order

For a manifest asset, the current effective order is:

1. exact namespace/path type observed in the current captured patch;
2. same-path type observed elsewhere in the same namespace group, only when all observed types agree;
3. patch-local `Packages.bin` parent -> type evidence;
4. patch-local unambiguous filename/suffix evidence;
5. matching current `Warframe.x64.exe` mappings;
6. same-namespace/path original-base CommonHeader type hint;
7. same-path original-base namespace-group CommonHeader type hint, only when all hints agree;
8. exact current-session OpenWF 404 type hint, only when a log was explicitly supplied;
9. unresolved.

There is an additional optimization before ordinary resolution:

- if the patch already contains the exact `(namespace, path, hash)` object under one unique
  type, verify and reuse that exact object directly.

The hierarchy is designed to prefer evidence closest to the target build and target patch.

---

# 13. Patch-local type learning

Existing captured OpenWF objects are especially valuable because their filenames already
encode the real type used by the CDN for that object.

The patch scanner parses objects matching the general form:

```text
<namespace><logical path>!<type>_<hash>
```

and records:

```text
namespace
logical_path
type_id
expected_hash
filesystem path
```

## 13.1 Exact path mappings

For each:

```text
(namespace, logical_path)
```

an exact type mapping is retained only when every observed object agrees on one type.

If the same path appears under two type IDs, the exact mapping is considered ambiguous and is
not used.

## 13.2 Exact object reuse

For:

```text
(namespace, logical_path, hash)
```

an exact reusable object is retained only when there is exactly one observed type.

This rule matters because keeping the first object encountered would silently bless a stale or
corrupt duplicate.

## 13.3 Filename/suffix learning

The repairer can learn that an observed filename pattern corresponds to a type.

Patterns come from:

- extension/pattern rows extracted from the matching executable; and
- ordinary suffixes observed in `/Lotus/`, `/EE/`, or `/Temp/` patch objects.

A pattern is usable only when it maps unambiguously to one type in its namespace group.

When several patterns match a path, the longest/specific pattern wins.

This allows a specific pattern such as a specialized `_skel.fbx` form to remain useful even if
a generic `.fbx` pattern is ambiguous.

### Why generic ambiguity is rejected

A filename extension is a hint, not a law. Warframe can use the same generic extension for
multiple internal types.

The repairer intentionally prefers `unresolved` over a convenient but unproven guess.

---

# 14. Packages.bin: what we use it for

`Packages.bin` provides relationships between logical entities and their parent/base types.

The repairer does **not** need to decode every property payload in Packages.bin. For type
resolution it primarily needs:

```text
child logical path -> parent type path
```

Those chains let the script correlate already-observed CDN types with semantic/native parent
classes.

This is much stronger than guessing from a filename alone.

---

# 15. Packages.bin v46 parser: verified U44 layout

The current standalone parser intentionally supports only:

```text
Packages.bin version 46
```

because that is the directory-block layout validated against real U44 repair workflows.

Earlier experimental fallback parsers were removed from the current source. Git history is the
right place to preserve unvalidated ideas; production repair should contain formats that are
known to work.

## 15.1 Fixed header checks

The current parser verifies:

```text
u32 @ 16 == 20      # header size
u32 @ 20 == 46      # Packages version
u32 @ 24 == 1       # flags
```

A version other than 46 is rejected.

This is deliberate. Do **not** change `version != 46` into a broad `version >= 46` test just to
make a future build run.

## 15.2 Why the locator does not use fixed build offsets

Real Packages.bin files are large and contain metadata/compressed regions before the entity
table. Hard-coding a byte offset from one build would be fragile.

The v46 locator instead anchors itself using structural invariants.

## 15.3 Zstandard dictionary anchor

The locator searches for the embedded full Zstandard dictionary magic:

```text
37 A4 30 EC
```

For a candidate dictionary offset:

```text
u32 immediately before dictionary -> comZ length
entity_count offset                -> dictionary_offset + comZ_length
u32 at entity_count offset         -> entity_count
```

Candidates with implausible lengths/counts are discarded.

## 15.4 Locating the entity table

After `entity_count`, the verified U44 sample contained nearby metadata before the directory
blocks. Instead of assuming the observed gap is universally 15 bytes, the code scans a small
bounded window (currently up to 8192 bytes) for a structurally plausible first directory block.

A candidate is accepted only after the parser can validate **exactly the advertised number of
entities**.

This is significantly stronger than accepting a position because one marker happens to match.

## 15.5 Directory-block structure

The v46 entity table is organized as shared-directory blocks.

The parser reads:

```text
u32 directory_length
directory bytes
u8  directory metadata
u32 entity_count_in_directory
```

Then each entity contains:

```text
u32 filename_length
filename bytes
3 bytes entity metadata
u32 parent_length
parent bytes
```

The one-byte directory metadata is intentionally treated as opaque.

### Why that byte is not hard-coded

One verified sample initially suggested a fixed marker such as `0x01`. Real U44.0.1 data later
contained `0x00` in other directory blocks, and the reference decoder simply advanced over the
byte.

Hard-coding `0x01` would therefore reject a valid real file.

That bug is exactly the kind of thing this document is intended to prevent from being
reintroduced.

## 15.6 Text decoding

Packages byte strings are decoded with latin-1 semantics after structural validation.

Most real paths are ordinary ASCII, but rejecting the entire table solely because one future
path has a high-bit byte would be unnecessarily fragile.

Embedded NULs/control-like path corruption are still rejected where appropriate.

## 15.7 Parent normalization

For each full child path:

```text
full_path = directory + filename
```

The parent is normalized as:

```text
empty parent        -> ""
absolute parent     -> parent as-is
relative parent     -> directory + parent
```

The resulting mapping is stored in `PackagesParentIndex.parents`.

Parent chains are followed with:

- cycle detection;
- a maximum depth of 128;
- stop on empty/missing parent.

## 15.8 Full structural validation before trust

The locator performs a complete dry parse without retaining the huge mapping first.

Only after a candidate table successfully parses all entities does the repairer perform the
second parse that collects the actual parent map.

The locator also limits unexplained trailing bytes after the parsed table. The purpose is not
to insist on one exact file size; it is to avoid accepting a false-positive table start in a
large binary.

---

# 16. Packages.bin selection, ambiguity and version gating

Captured patches can accumulate stale objects. Selection therefore happens in two separate
phases:

1. validate each candidate object's SHCC/container integrity and verify that the embedded target
   hash matches the `Packages.bin!TYPE_HASH` filename;
2. only after object selection is unambiguous, parse the selected Packages payload format.

Behavior:

```text
0 integrity-valid -> Packages evidence unavailable; continue with other evidence
1 integrity-valid -> parse that one object's Packages version/layout
>1 integrity-valid -> fatal PackagesAmbiguityError before format parsing
1 valid object with unsupported version -> fatal UnsupportedPackagesVersionError
1 valid supported-version object whose validated layout cannot be parsed -> fatal UnsupportedPackagesLayoutError
```

The order matters. If a stale U44 v46 object and a current future v47 object are both intact, the
repairer must **not** discard the v47 object merely because its parser is unsupported and then
silently choose the stale v46 object. Both are valid captured target candidates, so the capture is
ambiguous and must be cleaned first.

A previous implementation also raised an ambiguity error inside the loader but accidentally
caught it in generic `RepairError` handling and continued without Packages evidence.
`PackagesAmbiguityError`, `UnsupportedPackagesVersionError` and
`UnsupportedPackagesLayoutError` are now re-raised through the normal run path. Missing or
integrity-broken Packages metadata remains non-fatal because the repairer can still use other
independent type evidence. Once one Packages object has passed full object integrity, however, a
format/layout failure is compatibility evidence rather than absence of evidence and must stop the
run.

Do not collapse these compatibility errors back into the generic non-fatal Packages warning.

---

# 17. Packages parent -> type learning

Packages.bin alone gives parent relationships, not automatically the final CDN type number for
every child.

The repairer learns parent/type relationships by combining Packages chains with already
captured objects:

```text
observed object
    -> follow Packages parent chain
    -> associate each parent with observed object's type
```

Only parents that consistently map to one type in the relevant namespace group are retained.

If one parent is associated with multiple type IDs, that parent mapping is discarded as
ambiguous.

This lets a missing object inherit a strong type hint from a semantic parent relationship
without embedding a version-specific type table in Python.

---

# 18. Package-relative native parent normalization through the EXE

Packages can identify a parent using a path that is not identical to the executable's full
canonical native registration path.

For example, a parent can terminate in a native class name such as:

```text
MissionRewardItemManifest
```

while the EXE knows the class through a full path such as:

```text
/Lotus/Types/Game/MissionRewardItemManifest
```

The resolver can compare the **terminal native class name** with the native type table
extracted from the matching EXE.

This is accepted only if that basename maps to one unique type ID. Ambiguous native basenames
are rejected.

This is not arbitrary fuzzy matching. Packages supplies the semantic parent; the EXE supplies
the authoritative current-build type registration.

---

# 19. Warframe.x64.exe extraction

The repairer can derive type mappings from the matching `Warframe.x64.exe` without launching or
modifying the game.

Optional dependencies:

```text
pefile
capstone
```

are listed in `requirements.txt`.

If they are unavailable, or extraction fails, normal repair can still continue using
patch-local evidence, Packages evidence, base type hints, and optionally OpenWF fallback.
`extract_type_tables_from_exe()` is the subsystem boundary: expected extractor failures already
use `RepairError`, while unexpected parser/emulator exceptions are normalized into `RepairError`
there so a changed future executable cannot crash the entire repair with a raw traceback.

## 19.1 Why the EXE is better than an embedded table

A hard-coded mapping snapshot from U44 would be convenient but dangerous:

- a type can change in a newer build;
- shader mappings can differ by platform namespace;
- native registrations can be added/removed;
- a stale table can return a plausible-looking but wrong CDN URL.

The matching executable is much closer to an authoritative description of the target build.

## 19.2 PE sections used

The extractor relies on PE information including:

```text
.text
.rdata
.pdata
```

`.text` supplies code to inspect/emulate.

`.rdata` supplies strings, tables and vtable-like data.

`.pdata` supplies function start information used while recovering native registration call
sites.

## 19.3 Small x86-64 evaluator

The extractor does not execute Warframe code natively. It contains a deliberately small x86-64
evaluator for the instruction subset encountered in cache-type getter functions.

It models registers, a synthetic stack, flags, direct calls/jumps and selected arithmetic/data
movement instructions.

The evaluator intentionally fails on unsupported behavior rather than pretending to emulate a
complete process.

Examples of unsafe situations include:

- indirect calls/jumps not modeled by the evaluator;
- accesses to runtime object fields outside the synthetic stack;
- unsupported condition codes/instructions;
- too many unknown runtime globals.

This failure behavior is a feature. An incomplete emulator should not manufacture a type ID.

## 19.4 Extension/pattern rows

One extraction path finds extension-list getters in `.text`/`.rdata`, resolves the associated
cache-type getter, and evaluates it for the Windows platform.

The result is a set of `TypePatternRow` values:

```text
type_id
patterns[]
note
```

Shader/platform-dependent getters are handled separately where the extractor can safely resolve
known platform namespace values.

Current shader platform labels include:

```text
0x9 -> DX11 (Content/9)
0xA -> DX12 (Content/A)
```

## 19.5 Native registered types

The extractor also reconstructs native type registrations.

At a high level it:

1. locates a known graphics-resource package string;
2. uses call-site voting to identify the native registration function;
3. scans direct call sites to that function;
4. identifies the surrounding function boundaries using `.pdata`;
5. gathers package/class strings and factory-related code references;
6. recovers a vtable;
7. resolves the cache-type getter slot;
8. evaluates that getter for Windows;
9. stores canonical native path -> type mappings.

Platform-dependent native getters that cannot be safely treated as generic Content/0 mappings
are skipped.

## 19.6 Matching EXE location

The standalone script currently looks only for:

```text
<supplied-root>/Warframe.x64.exe
```

It does not recursively search for another executable. This avoids silently binding the repair
to an EXE from the wrong build.

---

# 20. Type resolver details

The resolver has two major sources:

```text
patch-local evidence
current EXE tables
```

and the calling repair path can then add:

```text
base CommonHeader hint
OpenWF exact 404 hint
```

## 20.1 Patch-local exact mapping

First choice inside patch resolution:

```text
(namespace, logical_path) -> one observed type
```

This is extremely direct evidence.

## 20.2 Patch-local same-path namespace-group mapping

If the exact namespace/path was not captured, the script next checks the same logical path in the
namespace group. `0`, `0_de`, `0_en`, `0_ja` and the other language/variant namespaces share
group `0`; DX11 and DX12 remain in their own groups. The fallback is retained only when every
observed type for that grouped path agrees. Conflicting types deliberately leave the asset
unresolved. This covers root-level service objects such as `/Languages.bin`, which do not pass
through Packages/filename-pattern learning.

## 20.3 Patch-local Packages parent mapping

If same-path evidence is absent, the script follows the target path's Packages parent chain and
checks whether one of those parents has an unambiguous type learned from the current patch.

## 20.4 Patch-local filename pattern

Next it checks unambiguous filename patterns in the relevant namespace group, preferring the
longest matching pattern.

## 20.5 Current EXE mapping

If patch-local evidence does not resolve the type, the current EXE is queried.

For ordinary namespace group `0`, native class resolution is attempted before extension
patterns.

Shader namespaces rely on the platform-aware extension rows rather than unsafe generic native
mapping.

## 20.6 Base CommonHeader type hints

Only after target-build patch/EXE evidence fails does normal repair use an unambiguous type
from the original base. The exact same namespace/path is preferred. If that exact hint is absent,
the same logical path may fall back across the namespace group when every available base hint
agrees on one type. This is especially useful when H.Cache restores a language manifest that was
missing from the captured patch and exposes a changed root-level object such as `/Languages.bin`.

Why is base evidence lower priority?

Because the base is an older build. Its type is often useful, but target-build evidence should
win if the target changed the registration.

## 20.7 OpenWF exact 404 fallback

Only when the user explicitly supplies `--openwf-log` can an exact current-session request
provide the final type fallback for the same:

```text
namespace
logical path
hash
```

This is highly specific evidence, but it is kept as a fallback so normal static repair does not
depend on running the client and producing a failure first.

---

# 21. OpenWF trace-log handling

OpenWF logs are optional diagnostics, not required repair input.

The repairer recognizes exact hashed 404 requests such as:

```text
GET /0/Lotus/.../Foo.lua!78_<hash> 404
GET /9/Lotus/.../Shader.hlsl!<type>_<hash> 404
GET /A/Lotus/.../Shader.hlsl!<type>_<hash> 404
```

## 21.1 Session boundary

A daily log can contain multiple server sessions.

The repairer finds the **last** line containing:

```text
Using log file:
```

and considers only 404s after that boundary.

If no current-session marker is present, it refuses to use the log for recovery rather than
falling back to all historical entries.

This prevents an old request from a different target build from contaminating the current
repair.

## 21.2 Ambiguous 404 types

If the same exact namespace/path/hash appears with conflicting types in the selected session,
the hint is discarded as ambiguous.

## 21.3 Manifest candidates vs direct recovery

For manifest candidates, an exact 404 type is only a fallback after static type resolution.

After manifest candidates are processed, exact 404 objects that are outside the relevant
manifest candidate set can still go through direct recovery. Section filters are respected
where the request can be identified as belonging to an omitted manifest object.

---

# 22. Section filtering and stripped assets

## 22.1 Default mode

All three manifest sections are selected:

```text
service
packed
stripped
```

## 22.2 `--no-stripped`

The `stripped` section is excluded before base comparison.

This matters because omitted stripped assets must not later appear as "unknown" and make the
run incomplete.

The option is non-destructive. If a stripped object is already present in the patch, the script
does not delete it.

## 22.3 `--only-stripped`

Only stripped-section entries are selected and compared against the base.

Changed/new stripped assets are exported to a **new separate output tree**:

```text
<output>/OpenWF/Content/...
```

The source patch is used as an evidence/source pool but is not modified. Before H.Cache/B.Cache
completion, the script copies only the captured manifest metadata (`H.Cache.bin` and `B.Cache.*`)
into a temporary staging directory. Any official H.Cache or missing B.Cache downloads are written
there, the completed manifests are parsed, and the staging directory is removed before stripped
asset repair begins. This keeps metadata recovery from mutating the source patch.

If a required exact object already exists in the source patch and verifies, it is copied to the
export. Otherwise the repairer resolves/downloads it normally.

Without `--stripped-output`, the output directory is timestamped:

```text
YYYY-MM-DD_HH-MM-SS_stripped-assets
```

A custom destination must not already exist. This prevents accidental merging with an older
export.

---

# 23. Why unchanged base assets normally do not belong in a patch

The patch is intended to update the original Steam base, not to become a complete standalone
copy of every target CDN object.

Therefore a target manifest entry whose hash is byte-for-byte identical to the original base
is normally omitted from repair candidates.

This is why pointing the repairer at only an update patch with no original base is insufficient
for general completion. Without the base, the script cannot distinguish:

```text
missing because capture failed
```

from:

```text
missing because the asset was already supplied by the base
```

FontCache is the known deliberate exception discussed earlier.

---

# 24. Why CachePlan.txt is not a correctness dependency

The standalone repairer derives its target inventory from the target manifests and its base
classification from Cache.Windows/CommonHeaders.

It does not require `CachePlan.txt` for correctness.

A future NCT-integrated implementation may use CachePlan information as an indexing or lookup
accelerator, but that should remain an optimization unless independently proven necessary for
correctness.

Keeping the correctness path independent makes archived v1.0 captures more repairable even if
auxiliary launcher files were not preserved.

---

# 25. Download behavior

The CDN base is:

```text
https://content.warframe.com/
```

For each exact resolved object name, the repairer performs up to three HTTP attempts through
PyCURL/libcurl. The transport uses a 30-second connection timeout and aborts a transfer that
stays below 1 byte/second for 30 seconds; redirects are followed up to five hops. TLS certificate
and hostname verification remain enabled.

Each worker thread keeps one libcurl easy handle in thread-local storage. The handle is reset
between object requests, but libcurl deliberately keeps its live connection/DNS/session caches
across `curl_easy_reset()`. This removes the old forced `Connection: close` request header and
allows successive assets handled by the same worker to reuse a compatible persistent connection.
With the default two repair workers this normally gives two independently reusable transfer
handles without replacing the existing bounded `ThreadPoolExecutor` repair pipeline with a second
concurrency model.

Transient-style status codes currently eligible for retry include:

```text
408 425 429 500 502 503 504
```

Other HTTP errors generally stop retries for that object because repeating the exact request is
unlikely to help.

A `200 OK` is **not** considered success until the body passes SHCC/container/hash verification.

A 200 response that is truncated/corrupt can therefore be retried within the same attempt
budget.

This distinction prevents a bad CDN/proxy/network body from being written merely because the
HTTP status was successful.

---

# 26. Atomic writes and disk-full handling

Downloaded/reused data is not written directly over the destination.

The repairer creates a same-directory temporary file:

```text
.wfpr-*.tmp
```

writes the complete verified object, then replaces the destination atomically with
`os.replace()`.

Benefits:

- an interrupted write does not leave a partially overwritten target object;
- replacement happens on the same volume;
- low disk space can be handled before committing the new object.

## 26.1 Disk reserve

The script keeps a safety headroom of:

```text
64 MiB
```

and warns once per output volume when free space falls to roughly:

```text
1 GiB or less
```

## 26.2 Pause/resume behavior

If the next complete atomic write cannot fit, or a real disk-full error occurs, the repairer
waits and periodically rechecks free space.

The already verified in-memory body can then be written without redownloading it.

If a single object is larger than what the volume can ever reasonably accommodate under the
required free-space calculation, the surrounding failure handling reports the problem rather
than converting a partial file into apparent success.

---

# 27. Windows path handling

The repairer validates Windows paths using modern filesystem limits rather than blindly
imposing legacy `MAX_PATH == 260`.

Current checks include:

```text
component <= 255 UTF-16 code units
full path <= 32760 UTF-16 code units
```

The purpose is to catch impossible output names while still permitting long-path-capable
Windows configurations.

Generated CDN paths are also checked against traversal/unsafe components such as empty,
`.` or `..` path segments.

---

# 28. Console behavior that is intentional

Long repair runs can involve thousands of objects. The console code therefore tries to avoid
turning progress into a huge permanent log.

Intentional behavior includes:

- transient progress rows for scans/parsing;
- stale characters from a longer transient frame are erased in-place and the cursor is returned to the end of the current frame instead of being left after invisible padding;
- visible download/save/verify progress for sufficiently large/slow objects;
- ANSI color only when the output stream supports it;
- `NO_COLOR` disables color;
- errors from external data are normalized to one console line;
- Windows QuickEdit is temporarily disabled so accidental mouse selection does not freeze a
  long repair;
- Ctrl+C exits with code 130.

These are usability features but are also operational safety features for multi-hour repair
runs.

---

# 29. CLI invariants

Current syntax:

```text
warframe_patch_repair.py [-h] [-t] [-l OPENWF_LOG] [-n | -s]
                         [-o STRIPPED_OUTPUT] [-w N]
                         [root] [base]
```

Current aliases:

```text
-h --help
-t --patch-types-only
-l --openwf-log
-n --no-stripped
-s --only-stripped
-o --stripped-output
-w --download-workers
```

Important parser/runtime behavior:

- long-option abbreviation is disabled;
- `-n` and `-s` are a normal argparse mutually-exclusive group;
- `--stripped-output` is validated after parsing and requires `--only-stripped`;
- `-w` / `--download-workers` defaults to 2 and accepts 1-16; `run()` enforces the same bound for direct callers;
- `run()` independently enforces the same mode contract for direct callers;
- the supplied Steam base/`Cache.Windows` (including the presence of at least one usable regular `H.<package>.toc` file)
  and an explicit OpenWF trace are validated before H.Cache/B.Cache completion is allowed to
  write anything into the patch;
- `--` retains argparse's standard end-of-options behavior.

Older revisions carried custom code solely to reject duplicate short/long alias spellings and
grouped short flags. That code did not protect repair correctness and added another CLI parser on
top of argparse, so it was removed. Standard argparse behavior is sufficient here.

---

# 30. Why several "helpful" guesses are forbidden

The repairer has repeatedly become more reliable by removing guesses, not adding more of them.

## 30.1 Do not turn one observed filename pattern into a universal hard-coded mapping

Patch-local filename learning may use a pattern when every observation for that pattern agrees,
even if the current patch contains only one observation. That is deliberately scoped evidence for
the current capture/build. Do not promote one such observation into a permanent global mapping or
assume the same extension must use that type in other builds/namespaces. If observations conflict,
the pattern is rejected rather than guessed.

## 30.2 Do not choose one of several Packages.bin files by mtime

Multiple valid target metadata objects mean the capture itself is ambiguous.

## 30.3 Do not merge stale target manifests

One cache family should describe one target build.

## 30.4 Do not assume all `version >= 46` Packages files use the v46 layout

Version numbers exist precisely because formats can change.

## 30.5 Do not treat language-looking filenames as namespace evidence

The owning manifest/cache family is authoritative.

## 30.6 Do not use historical OpenWF 404s by default

A daily log can contain requests from older builds/sessions.

## 30.7 Do not silently downgrade base read errors into "new asset"

Unreadable evidence means unknown, not absent.

## 30.8 Do not reconstruct target CDN bytes from an original-base cache merely because a logical
path exists there

The target bytes/hash/representation may differ. The exact CDN object is safer when available.

---

# 31. Known U44 validation results

The current design was developed using real U44 repair cases rather than synthetic format work
alone.

Important observed validation points include:

## U44.0.1

A repaired target completed with approximately:

```text
8,138 changed/new target objects
5,869 already present
2,269 downloaded
0 asset failures
0 skipped
```

## U44.0.2

One repair classification identified approximately:

```text
6,336 changed/new candidates
0 unknown base assets
```

U44.0.2 testing also exposed the special `0x43` whole-object wrapper behavior for real B7 HDR
and 8B WAV samples.

## U44.0.3

A full U44.0.3 repair against the original Steam base provided another real end-to-end validation:

```text
19/19 B.Cache manifests verified by captured H.Cache
489,082 unique target manifest objects
488,768 unchanged base objects
314 changed/new objects
0 unknown base objects
403 proactive FontCache additions
717 repair candidates
510 planned CDN downloads / 473.8 MiB / 2 workers
207 already present
510 downloaded
0 failed
0 skipped
0 manifest parse failures
verified + complete manifest coverage
```

The section accounting also balanced exactly: the 403 packed candidates were 207 present + 196
downloaded, while all 314 stripped candidates were downloaded. This run exercised the manifest
size planner, two-worker libcurl path, Packages/EXE/patch-local type evidence, language namespaces,
DX shader namespaces and a comparatively large stripped-asset update without unresolved types.

## FontCache follow-up

A runtime FontCache failure proved that base-identical FontCache objects can still be required
as CDN objects.

A later no-log FontCache coverage run processed:

```text
403 manifest FontCache candidates
263 already present
140 downloaded
0 failed
0 skipped
```

The exact counts are historical validation evidence, not future invariants.

---

# 32. What the current code does not promise

The repairer cannot guarantee that every historical Warframe update can be recovered forever.

A target manifest can correctly identify an exact object while Digital Extremes' CDN returns
404 because the bytes are no longer served.

That situation is distinct from a type-resolution or parser failure.

The script also does not promise:

- support for every historical Packages.bin version;
- support for every historical TOC/CommonHeader layout;
- support for future SHCC chunk/wrapper forms not yet observed;
- a generic Warframe filesystem reconstruction engine;
- a complete executable emulator;
- automatic compatibility with U45+.

Preservation copies of the original CDN objects remain valuable even when metadata survives.

---

# 33. U45 / future-build validation checklist

When a new content update arrives, do not immediately widen parser conditions. Work through this
checklist.

## 33.1 Preserve inputs first

Keep untouched copies of:

- original Steam base used for the update;
- target/update capture;
- target `Warframe.x64.exe`;
- every captured `B.Cache.*` manifest;
- captured `H.Cache.bin` when available;
- captured `Packages.bin` object(s);
- NCT logs/session metadata;
- OpenWF trace if runtime testing produces requests.

## 33.2 Check target manifests

Confirm:

- SHCC validation still passes;
- record the exact manifest `u32 version` value before changing parser gates;
- manifest header begins with the expected embedded-hash/version area;
- service/packed/stripped ordering still matches;
- entry framing still matches path length + path + 16-byte hash + info;
- decoded payload is consumed exactly with no unexplained trailing bytes;
- namespace naming conventions have not changed;
- H.Cache still maps the target B.Cache family set/path hashes using the structurally parsed meta-manifest layout.

If any of these fail, fix/document the manifest parser before trusting candidate counts.

## 33.3 Check Packages.bin version first

Read the real version field.

If it is still `46`, validate that the existing locator/entity parser successfully parses the
whole table and produces sensible parent relationships.

If it is `47` or another version:

- do not change the condition to `>= 46`;
- inspect the new format independently;
- document similarities/differences;
- add a separate validated parser path only after real-data verification.

## 33.4 Check Packages ambiguity

Ensure the capture does not contain multiple valid target Packages objects from different
runs/builds.

## 33.5 Check EXE extraction

Verify that:

- PE sections used by the extractor still exist;
- extension mapping extraction produces plausible counts;
- native registration discovery still works;
- shader/platform mappings still separate DX11/DX12 correctly;
- newly unsupported instructions do not cause silent bad values.

If extraction fails, prefer a visible warning and other evidence over expanding the emulator
without understanding the new code pattern.

## 33.6 Check base cache formats

Confirm:

- H TOC magic/version are accepted because they really match the format;
- entry struct layout still matches;
- compression framing still behaves as expected;
- CommonHeader first 16 bytes still correspond to manifest hash;
- type-field traversal remains correct.

## 33.7 Check SHCC representations

Collect examples across several type families.

Verify:

- direct `0x52` CRC form still exists/works;
- `0x43` whole-object wrapper behavior has not changed;
- new wrapper markers/chunk types are not being mistaken for corruption;
- embedded target hash is still where expected.

## 33.8 Run static completion before relying on OpenWF

A healthy repair should resolve as much as possible from:

```text
manifests + base + patch + Packages + EXE
```

Use runtime 404s to investigate gaps, not to hide a systematic parser regression.

## 33.9 Test the repaired client

At minimum:

- launch client;
- login;
- inspect OpenWF/server requests for unexpected missing assets;
- exercise language variants if preserved;
- exercise both DirectX variants if preserved;
- watch for preprocessing/FontCache requests;
- keep logs for any residual 404s.

## 33.10 Update this document with observed evidence

If U45 confirms an assumption, say so explicitly.

If U45 breaks an assumption, document the exact old/new structure and why the code changed.

---

# 34. Regression tests and remaining matrix

The release includes `tests/test_warframe_patch_repair.py`. From the project root run:

```text
py -B -m unittest discover -s tests -v
```

From inside the `tests` directory run:

```text
py -B -m unittest discover -s . -v
```

Or run the test file directly from `tests`:

```text
py -B test_warframe_patch_repair.py -v
```

Tests that exercise transient progress directly capture the repairer's stdout. This is intentional: the production progress renderer uses carriage returns on an interactive console, which would otherwise overwrite `unittest -v` status rows even though the tests themselves pass. The repair script's normal progress behavior is unchanged. On Windows the test module enables console VT processing before `unittest` creates its result object, preserving Python 3.14's normal colored `ok`/`OK` output without relying on repair progress to enable VT as an accidental side effect.

The documented commands use `-B`, so running the suite does not create `.pyc`/`__pycache__` files. Repository hygiene is intentionally small: `.gitignore` still excludes Python cache/test-environment artifacts, and `.gitattributes` normalizes text source/docs to LF while marking bundled binaries/archives as binary. Do not broaden the ignore list to captured logs, fixtures, or Warframe research data without a concrete reason; those may be intentional inputs.

The focused suite currently contains 72 tests and covers the failure modes most likely to
create a misleading future repair result:

- H.Cache origin URL/type selection, structural parsing and embedded self-hash verification;
- H.Cache target matching requires every captured B.Cache overlap to agree;
- verified H.Cache metadata recovers missing B.Cache manifest objects before asset parsing, including independent missing DX11 and DX12 families;
- a valid captured H.Cache can bootstrap the full manifest family set with zero initial B.Cache files;
- an unprovable H.Cache/B.Cache target produces an explicit unverified coverage state, and unknown future coverage-state strings fail closed;
- the top-level run returns non-zero and never prints success when manifest coverage is unverified;
- stripped-only manifest metadata is staged separately, including a recovery-path test that proves missing B.Cache downloads cannot mutate the source patch;
- captured/local and official H.Cache inputs are bounded by the same fixed 16 MiB limit, with official responses checked against both advertised and streamed sizes;
- invalid direct `run()` mode combinations fail before content discovery, and invalid Steam-base/OpenWF-log inputs fail before manifest completion can mutate the patch;
- an empty base `Cache.Windows`, one containing only an `H.*.toc` directory, or one containing only an empty-package `H..toc` file is rejected before manifest completion can mutate the patch;
- Packages ambiguity is decided from integrity-valid objects before format parsing;
- one unsupported Packages version raises `UnsupportedPackagesVersionError`;
- one integrity-valid supported-version object with an unreadable layout raises `UnsupportedPackagesLayoutError`;
- one v46 Packages object reaches the normal parser;
- unexpected EXE extractor exceptions are normalized to `RepairError`;
- existing extractor `RepairError` values are preserved;
- manifest version 14 is accepted while unsupported versions are fatal and propagate out of manifest collection;
- manifest truncation and unexplained trailing decoded-manifest bytes are rejected;
- a sanitized real U44.0.2 `B.Cache.Windows_de.bin` header validates the real v14 section/path layout;
- real manifest `info` metadata is retained and a >16 MiB `0x2150EF7E` fixture proves the 28-bit CDN-size mask;
- manifest CDN planning returns the exact objects that still require a download, sums their 28-bit manifest sizes and excludes already-valid local objects;
- the default two-worker manifest downloader actually overlaps two worker threads, while worker count 1 stays on the sequential path and `-w` forwards an explicit worker count;
- completed planned downloads are emitted immediately as permanent rows while the aggregate progress row is restored below them;
- verified non-download preflight results can be reused by the result pass instead of immediately re-reading the same local object;
- manifest type fallback priority is centralized so preflight and the actual repair path cannot drift;
- global download progress tracks simultaneous per-worker attempts, rolls failed retry bytes back from completion, suppresses per-file verification rows while active and adjusts the planned total when a verified response size differs;
- libcurl transport tests prove same-thread easy-handle reuse across successive objects, omit the old `Connection: close` header, ignore redirect response bodies/lengths before the final 200 response, preserve bounded response-size failures and retry transient HTTP status codes on the same reusable handle;
- transient-line coverage proves stale-tail padding returns the visible cursor to the end of the current frame instead of leaving it at the erased previous width;
- CRC32C has known-vector coverage for the Python fallback and exercises native `google-crc32c` dispatch through the same public checksum interface;
- `_de` and `_xx` manifest ownership controls the `0_de`/`0_xx` namespace even for `_en`-named assets, including a VO-style `_en.wav` owned by `Windows_zh`;
- root-level `/Languages.bin` type resolution can reuse unambiguous same-path evidence across `Content/0*` language namespaces, while conflicting cross-language evidence remains unresolved;
- DX11/DX12 patch-local evidence remains isolated (`9` vs `A`), and representative `H.*Dx11` / `H.*Dx12` base packages map to the corresponding namespace without cross-fallback;
- original-base same-path namespace-group CommonHeader hints provide the same conservative fallback when patch-local evidence is absent;
- manifest filename grammar accepts only unsuffixed DX11/DX12 and optional ASCII-alphanumeric Windows suffixes;
- duplicate same-family target manifests are rejected instead of allowing stale manifest mixing;
- truncated decoded manifests remain per-manifest parse failures rather than escaping the collection boundary;
- direct SHCC CRC32C success/failure and embedded target-hash mismatch behavior are exercised;
- the observed outer `0x43` whole-object wrapper is exercised for valid and corrupted CRC32C cases;
- Oodle chunk payloads with unexplained trailing bytes are rejected;
- malformed/truncated LZF streams, invalid back-references, and decompressed-size mismatches are rejected;
- equal-sized framed Cache.Windows blocks are copied raw without invoking Oodle/LZF;
- atomic writes retry synthetic disk-full failures during temporary-file creation and replacement while preserving the old destination until replacement succeeds and cleaning temporary files;
- OpenWF exact 404 recovery is scoped to the latest `Using log file:` session boundary, while a log with no marker contributes no recovery objects;
- Packages and Cache.Windows directory-enumeration errors are preserved instead of being misreported as missing data.

These focused tests do not replace real Warframe fixtures. The broader matrix should continue
to distinguish synthetic unit coverage from retained real-format evidence.

## 34.1 Additional synthetic tests

Useful additional cases include:

- manifest truncation at every field boundary;
- duplicate manifest entries;
- Packages v46 truncated directory/entity fields;
- Packages opaque directory metadata `0x00` and `0x01`;
- parent cycles;
- ambiguous exact type mapping;
- ambiguous filename pattern;
- ambiguous Packages parent mapping;
- ambiguous OpenWF exact 404 type;
- Windows overlong path component;

## 34.2 Real fixture tests

Keep small legally/operationally appropriate metadata fixtures where possible for:

- U44.0.1 Packages.bin v46 structural parser;
- U44.0.2 wrapped B7/8B objects;
- representative target manifests, including the retained sanitized real U44.0.2 language header;
- representative H TOC/CommonHeader entries;
- EXE-derived type extraction outputs or sanitized expected mappings.

The supplied U44.0.1/U44.0.2 B.Cache research set establishes version 14 across all 38
manifest objects, including the large decoder-type-12 families. The embedded sanitized test
fixture keeps one real manifest structure in the normal regression suite without retaining its
original embedded object hash or target hashes.

Real fixtures catch the exact category of mistake that synthetic tests often miss: a parser can
be internally consistent while modeling the real binary incorrectly.

---

# 35. Code map for maintainers and AI assistants

Function names can move over time, but the current source is organized roughly like this.

## Console, filesystem and CLI safety

```text
_enable_console_colors
print_error / print_warning / print_retry
_validate_windows_output_path
_wait_for_disk_space
TransientLine
ActivityProgress
DownloadProgress
windows_quick_edit_disabled
RepairArgumentParser
```

## H.Cache / target-manifest completion

```text
parse_h_cache_header
h_cache_files
_h_cache_b_cache_entries
_h_cache_matches_captured
_download_official_h_cache
_matching_h_cache_index
complete_target_manifests_from_h_cache
_stage_manifest_evidence
```

## EXE/type extraction

```text
_WarframeTypeExtractor
extract_type_tables_from_exe
find_warframe_exe
TypeResolver
scan_existing_content_objects
build_patch_type_evidence
build_type_resolver
```

## SHCC/Oodle

```text
Oodle
_chunk_header
_decompress_oodle_payload
_decode_chunk
_unwrap_outer_compressed_shcc
shcc_header_and_hash
validate_shcc
verify_shcc
```

## Target manifests

```text
_manifest_header_version
parse_manifest_header
manifest_files
resolve_content_root
collect_manifest_assets
_dedupe_manifest_assets
```

## CDN/download/write

```text
cache_name
cdn_url
local_path
download_asset
plan_manifest_downloads
repair_planned_manifest_downloads
atomic_write
repair_object
```

## Base Cache.Windows

```text
iter_toc_entries
find_cache_windows_dir
_warframe_block_lens
lzf_decompress
read_cache_entry_raw
decompress_cache_entry
parse_common_header
BaseHeaderCache
classify_manifest_against_base
```

## OpenWF fallback

```text
extract_openwf_missing_objects
prepare_openwf_404s
_openwf_type_hints
_filter_openwf_by_section
_strip_manifest_404s
```

## Packages.bin

```text
PackagesParentIndex
_packages_v46_dir_block_candidate
_parse_packages_v46_entity_table
_locate_packages_v46
_read_packages_parent_index_v46
_read_packages_parent_index
_find_packages_objects
_load_packages_parent_index
_packages_parent_chain
```

## High-level repair

```text
resolve_manifest_asset_type
repair_manifest_asset
_select_manifest_sections
_create_stripped_output_root
run
main
```

When changing one subsystem, inspect the callers above and below it. Type resolution in
particular spans multiple layers and is easy to accidentally reorder.

---

# 36. Data-flow summary

Normal repair can be summarized as:

```text
PATCH ROOT
  |
  +--> locate OpenWF/Content
  |
  +--> load/verify captured H.Cache or fetch the official DE sentinel H.Cache
  |       |
  |       +--> compare every overlapping captured B.Cache hash
  |       +--> captured H.Cache may bootstrap zero-B.Cache captures
  |       +--> recover any missing B.Cache families by exact target hash
  |       +--> mark coverage verified or unverified
  |
  +--> validate/parse the completed target B.Cache manifest set
  |       |
  |       +--> namespace + section + logical path + target hash
  |
  +--> scan existing captured CDN objects
  |       |
  |       +--> exact type evidence
  |       +--> exact reusable object evidence
  |       +--> filename-pattern evidence
  |
  +--> validate/parse one unambiguous Packages.bin v46
  |       |
  |       +--> child -> parent chains
  |       +--> parent/type correlations with captured objects
  |
  +--> optionally extract matching Warframe.x64.exe mappings
  |       |
  |       +--> extension/pattern -> type
  |       +--> native class -> type
  |
  +--> ORIGINAL BASE Cache.Windows
  |       |
  |       +--> namespace/path -> CommonHeader hash
  |       +--> optional same-path type hint
  |       +--> unchanged / changed / new / unknown
  |
  +--> select changed/new
  |       +--> add all manifest FontCache targets
  |
  +--> for each candidate
          |
          +--> exact verified captured object? -> keep/copy
          |
          +--> resolve type
          |       1 patch exact
          |       2 patch Packages parent
          |       3 patch filename pattern
          |       4 current EXE
          |       5 base CommonHeader hint
          |       6 exact current-session OpenWF 404
          |
          +--> construct exact CDN name
          +--> verify existing destination if present
          +--> download if needed
          +--> verify SHCC/container/hash
          +--> atomic write
          |
          +--> summarize section/result
```

---

# 37. Stability-first maintenance and maintainer checklist

This project has enough binary-format and lifecycle complexity that defensive code can itself
create regressions. Prefer this order:

1. preserve working behavior;
2. fix empirically observed bugs;
3. add support for a new format only when a real file requires it;
4. prefer explicit failure over speculative recovery;
5. test against actual Windows/game/OpenWF workflows after parser changes;
6. keep research-only analyzers out of the normal repair path once their findings are incorporated.

Before changing parser/resolution behavior, answer:

1. Which real file or observed runtime failure requires the change?
2. Is the evidence target-build-specific, base-build-specific, or generic?
3. Can ambiguity be represented explicitly instead of guessed away?
4. Does this alter type-evidence precedence?
5. Could a parse failure now be mistaken for absence/new content?
6. Could stale capture files become silently selected?
7. Have direct SHCC and `0x43` wrapper objects both been regression-tested?
8. Have language, DX11 and DX12 namespaces remained isolated correctly?
9. Does the change still work without an OpenWF log?
10. Does a successful run still mean every selected candidate was verified or explicitly accounted for?

Common examples follow directly from those rules: do not widen Packages v46 to `>= 46`, do not
turn `.wav` or another extension into a universal type, do not choose the newest of multiple
Packages objects, do not classify a base read failure as a new target asset, and do not search
historical OpenWF logs for a convenient type answer.

Git history is the right archive for experiments. Production code should describe formats we
actually trust.

---

# 39. Relationship to Ninja Capture Tool / Ninja Patch Tool

This is a standalone repair script for Ninja Capture Tool/OpenWF captures. Its original
validation set was created with NCT v1.0-era captures; NCT v1.1 is intended to integrate this
repair workflow directly because it already knows more about the capture session and can invoke
repair at the appropriate point.

After that integration, the standalone implementation remains useful as:

- a reference algorithm;
- a recovery script for old captures;
- a format research baseline;
- a regression oracle when refactoring NCT integration.

Ninja Patch Tool is a different layer: it produces/applies file-level installation diffs.
This repairer operates on the Warframe CDN/OpenWF object set needed to make a captured update
patch complete before such higher-level preservation workflows rely on it.

Do not mix NPT's base semantics with this repairer's CDN-object classification logic.

---

# 40. Research provenance for the integrated EXE type extractor

The one-file `_WarframeTypeExtractor` did not originate as a fresh speculative implementation in
this repair script. It was adapted from two project research-reference scripts retained during
development:

```text
find_types.py
wfemu.py
```

The recovered reference copies used for this maintenance audit have these SHA-256 values:

```text
ad7d90a171bbad646b1c50c49024504ef8d2349358b9ff56890f5074fe9e081f  find_types.py
2c58202f55f477b122a8c96137d33f7c3f343ce0296779d2c627e870ea164034  wfemu.py
```

`find_types.py` performs the higher-level cache-type discovery: it finds extension getters,
resolves platform-dependent type functions, and reconstructs native registered type mappings.
`wfemu.py` contains the small x86-64 evaluator and PE-image helpers used by that research path.
The repairer integrates the required behavior so those files are **not runtime dependencies**.

This provenance matters for future maintenance. If a newer `Warframe.x64.exe` breaks extraction,
compare the integrated code against the reference algorithm and the new executable pattern before
adding emulator instructions or heuristics. A raw extractor failure should remain optional/fallback
behavior unless real evidence establishes the new pattern. Do not replace target-build extraction
with a hard-coded U44 type table merely because that would be simpler.

