#!/usr/bin/env python3
# Repairs incomplete Warframe update patches created with Ninja Capture Tool v1.0 for OpenWF using target-build metadata.
# Older target builds may reference CDN assets that are no longer available and return 404.
from __future__ import annotations

import argparse
import base64
import bisect
import ctypes
import errno
import hashlib
import os
import re
import struct
import sys
import tempfile
import time
import shutil
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

CDN_BASE = "https://content.warframe.com/"
HTTP_TIMEOUT = 30
HTTP_ATTEMPTS = 3
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)

# The full release archive bundles the exact Oodle runtime used by the repair
# tool next to this script. Keep its pinned identity so a damaged or replaced
# DLL fails explicitly instead of producing misleading decompression errors.
OODLE_DLL_NAME = "oo2core_9.dll"
OODLE_X64_SHA256 = "19452ae1abae65e1305d3818354d4fae7b1200294322f0d9c6d5ddeb7bd9f978"
OODLE_X64_SIZE = 582656
SUPPORTED_MANIFEST_VERSION = 14
VERIFY_PROGRESS_MIN_BYTES = 16 * 1024 * 1024
DISK_LOW_WARNING_BYTES = 1 * 1024 * 1024 * 1024
DISK_SAFETY_HEADROOM_BYTES = 64 * 1024 * 1024
DISK_WAIT_INTERVAL_SECONDS = 0.5
_WINDOWS_MAX_COMPONENT_UTF16 = 255
_WINDOWS_MAX_PATH_UTF16 = 32760
_LOW_DISK_WARNED: set[str] = set()

ANSI_GREEN = "\x1b[92m"
ANSI_YELLOW = "\x1b[93m"
ANSI_RED = "\x1b[91m"
ANSI_CYAN = "\x1b[36m"
ANSI_RESET = "\x1b[0m"
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_COLOR_SUPPORT: dict[int, bool] = {}

def _enable_console_colors(stream) -> bool:
    key = id(stream)
    cached = _COLOR_SUPPORT.get(key)
    if cached is not None:
        return cached

    if not getattr(stream, "isatty", lambda: False)() or os.environ.get("NO_COLOR") is not None:
        _COLOR_SUPPORT[key] = False
        return False
    if os.name != "nt":
        _COLOR_SUPPORT[key] = True
        return True

    try:
        handle_id = -12 if stream is sys.stderr else -11
        handle = ctypes.windll.kernel32.GetStdHandle(handle_id)
        mode = ctypes.c_uint()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            supported = False
        elif mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            supported = True
        else:
            supported = bool(
                ctypes.windll.kernel32.SetConsoleMode(
                    handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                )
            )
    except (AttributeError, OSError):
        supported = False

    _COLOR_SUPPORT[key] = supported
    return supported

def _color(text: str, ansi: str, stream) -> str:
    if not _enable_console_colors(stream):
        return text
    return f"{ansi}{text}{ANSI_RESET}"

def _single_line_console_text(value: object) -> str:
    """Keep externally supplied error/status text on one console row."""
    return re.sub(r"[\x00-\x1F\x7F]+", " ", str(value)).strip()

def print_error(message: str, *, file=None) -> None:
    stream = file or sys.stderr
    message = _single_line_console_text(message)
    print(f"{_color('ERROR:', ANSI_RED, stream)} {message}", file=stream)

def print_warning(message: str, *, prefix: str | None = None, file=None) -> None:
    stream = file or sys.stdout
    message = _single_line_console_text(message)
    warning = _color("WARNING:", ANSI_YELLOW, stream)
    if prefix:
        print(f"{prefix} {warning} {message}", file=stream)
    else:
        print(f"{warning} {message}", file=stream)

def print_retry(attempt: int, message: str, display_name: str) -> None:
    token = _color("[Retry]", ANSI_YELLOW, sys.stdout)
    message = _single_line_console_text(message)
    display_name = _single_line_console_text(display_name)
    print(f"{token} {attempt}/{HTTP_ATTEMPTS} | {message} | {display_name}")

def _http_status_color(status: int) -> str | None:
    if 200 <= status < 300 and status != 206:
        return ANSI_GREEN
    if status == 206 or 300 <= status < 400:
        return ANSI_YELLOW
    if 400 <= status < 600:
        return ANSI_RED
    return None

def http_status_label(status: int) -> str:
    color = _http_status_color(status)
    token = str(status) if color is None else _color(str(status), color, sys.stdout)
    return f"[{token}]"

def _format_bytes(value: int) -> str:
    size = float(max(0, value))
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0

def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")

def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2

def _validate_windows_output_path(path: Path, *, label: str = "Output path") -> Path:
    """Validate the real Windows filesystem limits without imposing legacy MAX_PATH."""
    if os.name != "nt":
        return path

    for part in path.parts:
        if part in {path.anchor, "\\"} or (len(part) == 3 and part[1:] == ":\\"):
            continue
        if _utf16_units(part) > _WINDOWS_MAX_COMPONENT_UTF16:
            raise RepairError(
                f"{label} component exceeds the Windows 255 UTF-16-unit limit: {part!r}"
            )

    if _utf16_units(str(path)) > _WINDOWS_MAX_PATH_UTF16:
        raise RepairError(
            f"{label} exceeds the Windows path-length limit and cannot be used: {path}"
        )
    return path

def _existing_disk_anchor(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    return candidate

def _disk_volume_key(path: Path) -> str:
    if os.name == "nt":
        drive = path.drive
        return drive.casefold() if drive else str(path.anchor).casefold()
    try:
        return f"dev:{path.stat().st_dev}"
    except OSError:
        return str(path.resolve())

def _warn_low_disk_space(path: Path, free: int) -> None:
    if free > DISK_LOW_WARNING_BYTES:
        return
    key = _disk_volume_key(path)
    if key in _LOW_DISK_WARNED:
        return
    _LOW_DISK_WARNED.add(key)
    print_warning(
        f"Only {_format_bytes(free)} of free space remains on the output drive ({path.anchor or path})."
    )

def _is_disk_full_error(exc: OSError) -> bool:
    disk_errnos = {errno.ENOSPC}
    edquot = getattr(errno, "EDQUOT", None)
    if edquot is not None:
        disk_errnos.add(edquot)
    return exc.errno in disk_errnos or getattr(exc, "winerror", None) in {39, 112}

def _wait_for_disk_space(
    path: Path,
    required_bytes: int,
    display_name: str,
) -> None:
    """Wait until the destination volume can hold the next atomic write safely."""
    required_bytes = max(0, int(required_bytes))
    needed = required_bytes + DISK_SAFETY_HEADROOM_BYTES
    line = TransientLine(min_interval=0.20)
    waiting = False
    try:
        while True:
            anchor = _existing_disk_anchor(path)
            usage = shutil.disk_usage(anchor)
            free = int(usage.free)
            _warn_low_disk_space(anchor, free)

            if needed > int(usage.total):
                raise RepairError(
                    f"{_format_bytes(needed)} would be required on the output volume for {display_name}, "
                    f"but the volume capacity is only {_format_bytes(int(usage.total))}."
                )
            if free >= needed:
                return

            waiting = True
            plain_prefix = (
                f"[Waiting] {_format_bytes(needed)} needed / {_format_bytes(free)} available "
                f"| Free disk space to continue | "
            )
            styled_prefix = (
                f"[Waiting] {_color(_format_bytes(needed), ANSI_CYAN, sys.stdout)} needed / "
                f"{_format_bytes(free)} available | Free disk space to continue | "
            )
            width = max(20, shutil.get_terminal_size((120, 24)).columns)
            available = max(4, width - len(plain_prefix) - 1)
            shown = display_name
            if len(shown) > available:
                shown = shown[-available:] if available <= 3 else "..." + shown[-(available - 3):]
            line.render(styled_prefix + shown, plain_prefix + shown, force=True)
            time.sleep(DISK_WAIT_INTERVAL_SECONDS)
    finally:
        if waiting:
            line.finish()

def _ensure_directory_with_disk_wait(path: Path, display_name: str) -> None:
    _validate_windows_output_path(path, label="Output directory")
    while True:
        try:
            path.mkdir(parents=True, exist_ok=True)
            return
        except OSError as exc:
            if not _is_disk_full_error(exc):
                raise
            _wait_for_disk_space(path.parent, 0, display_name)

class TransientLine:
    """Single-line interactive status renderer that overwrites in place.

    A refresh writes the new frame first and only pads any remainder from the
    previous frame. It never clears the row before drawing the replacement,
    avoiding the blank-frame flicker that a clear-then-redraw loop can cause.
    """

    def __init__(self, *, min_interval: float = 0.10, show_after: float = 0.0):
        self.min_interval = min_interval
        self.show_after = show_after
        self.started = time.monotonic()
        self.last_render = 0.0
        self.interactive = bool(getattr(sys.stdout, "isatty", lambda: False)())
        self._visible = False
        self._previous_width = 0

    def render(
        self,
        styled_text: str,
        plain_text: str,
        *,
        force: bool = False,
    ) -> bool:
        if not self.interactive:
            return False
        now = time.monotonic()
        if not self._visible and now - self.started < self.show_after:
            return False
        if not force and now - self.last_render < self.min_interval:
            return False
        self.last_render = now

        # Callers keep their frame below the terminal width. Padding is appended
        # in the same write so shorter updates cannot leave stale characters and
        # no empty frame is displayed between updates.
        visible_width = len(plain_text)
        columns = max(1, shutil.get_terminal_size((120, 24)).columns)
        max_padding = max(0, columns - 1 - visible_width)
        padding = " " * min(
            max(0, self._previous_width - visible_width),
            max_padding,
        )
        sys.stdout.write("\r" + styled_text + padding)
        sys.stdout.flush()
        self._previous_width = visible_width
        self._visible = True
        return True

    def finish(self, *, defer_flush: bool = False) -> None:
        if not self.interactive or not self._visible:
            return
        columns = max(1, shutil.get_terminal_size((120, 24)).columns)
        clear_width = min(self._previous_width, max(0, columns - 1))
        sys.stdout.write("\r" + (" " * clear_width) + "\r")
        if not defer_flush:
            sys.stdout.flush()
        self._visible = False
        self._previous_width = 0

class ActivityProgress:
    def __init__(
        self,
        label: str,
        total: int | None = None,
        *,
        show_after: float = 0.15,
    ):
        self.label = label
        self.total = total if total is not None and total >= 0 else None
        self.current = 0
        self.started = time.monotonic()
        self.line = TransientLine(show_after=show_after)

    def update(
        self,
        current: int,
        *,
        detail: str | None = None,
        extra: str | None = None,
        force: bool = False,
    ) -> None:
        self.current = max(0, current)
        if not self.line.interactive:
            return

        if self.total is not None and self.total > 0:
            percent = min(100.0, self.current * 100.0 / self.total)
            active = f"{self.current} / {self.total} ({percent:.1f}%)"
        else:
            active = f"{self.current}"

        elapsed = max(0.0, time.monotonic() - self.started)
        rate = (
            f"{self.current / elapsed:.0f}/s"
            if elapsed >= 0.5 and self.current > 0
            else None
        )

        width = max(20, shutil.get_terminal_size((120, 24)).columns)
        max_width = max(1, width - 1)
        plain_prefix = f"[{self.label}] {active}"
        styled_prefix = f"[{self.label}] {_color(active, ANSI_CYAN, sys.stdout)}"
        if len(plain_prefix) > max_width and self.total is not None and self.total > 0:
            percent = min(100.0, self.current * 100.0 / self.total)
            active = f"{percent:.1f}%"
            plain_prefix = f"[{self.label}] {active}"
            styled_prefix = f"[{self.label}] {_color(active, ANSI_CYAN, sys.stdout)}"
        if len(plain_prefix) > max_width:
            active = f"{self.current}"
            plain_prefix = f"[{self.label}] {active}"
            styled_prefix = f"[{self.label}] {_color(active, ANSI_CYAN, sys.stdout)}"

        # Prefer the operation-specific counters over the generic rate when a
        # narrow terminal cannot fit both. Never allow a transient frame to wrap.
        pieces: list[str] = []
        if rate:
            pieces.append(rate)
        if extra:
            pieces.append(extra)
        middle = "" if not pieces else " | " + " | ".join(pieces)
        if len(plain_prefix) + len(middle) > max_width and rate and extra:
            middle = " | " + extra
        if len(plain_prefix) + len(middle) > max_width:
            available = max(0, max_width - len(plain_prefix) - 3)
            if available > 0:
                raw_middle = middle[3:] if middle.startswith(" | ") else middle
                if len(raw_middle) > available:
                    raw_middle = raw_middle[:max(0, available - 3)] + "..."
                middle = " | " + raw_middle
            else:
                middle = ""

        suffix = ""
        if detail:
            fixed = len(plain_prefix) + len(middle) + 3
            available = max(0, max_width - fixed)
            if available > 0:
                if len(detail) <= available:
                    shown_detail = detail
                elif available <= 3:
                    shown_detail = detail[-available:]
                else:
                    shown_detail = "..." + detail[-(available - 3):]
                suffix = " | " + shown_detail

        plain = plain_prefix + middle + suffix
        styled = styled_prefix + middle + suffix
        self.line.render(styled, plain, force=force)

    def finish(self) -> None:
        self.line.finish()

class DownloadProgress:
    def __init__(
        self,
        name: str,
        total: int | None,
        *,
        label: str = "Downloading",
        show_after: float = 0.0,
    ):
        self.name = name
        self.label = label
        self.total = total if total is not None and total >= 0 else None
        self.completed = 0
        self.samples: deque[tuple[float, int]] = deque([(time.monotonic(), 0)])
        self.line = TransientLine(show_after=show_after)

    def _speed(self, now: float) -> float:
        self.samples.append((now, self.completed))
        while len(self.samples) > 1 and now - self.samples[0][0] > 2.0:
            self.samples.popleft()
        if len(self.samples) < 2:
            return 0.0
        elapsed = self.samples[-1][0] - self.samples[0][0]
        if elapsed <= 0:
            return 0.0
        return (self.samples[-1][1] - self.samples[0][1]) / elapsed

    def _display_path(self, prefix_len: int) -> str:
        width = shutil.get_terminal_size((120, 24)).columns
        available = max(4, width - prefix_len - 1)
        if len(self.name) <= available:
            return self.name
        if available <= 3:
            return self.name[-available:]
        return "..." + self.name[-(available - 3):]

    def update(self, amount: int, *, force: bool = False) -> None:
        self.completed += amount
        if not self.line.interactive:
            return
        now = time.monotonic()
        speed = self._speed(now)
        if self.total is not None and self.total > 0:
            percent = min(100.0, self.completed * 100.0 / self.total)
            progress = f"{_format_bytes(self.completed)} / {_format_bytes(self.total)} ({percent:.1f}%)"
        else:
            progress = _format_bytes(self.completed)
        speed_text = f"{_format_bytes(int(speed))}/s"
        width = max(20, shutil.get_terminal_size((120, 24)).columns)
        plain_prefix = f"[{self.label}] {progress} | {speed_text} | "
        styled_prefix = (
            f"[{self.label}] {_color(progress, ANSI_CYAN, sys.stdout)} | {speed_text} | "
        )

        # Keep a useful path tail visible on narrow consoles instead of letting
        # the transient row wrap onto a second line.
        if len(plain_prefix) + 4 > width - 1 and self.total is not None and self.total > 0:
            percent = min(100.0, self.completed * 100.0 / self.total)
            progress = f"{percent:.1f}%"
            plain_prefix = f"[{self.label}] {progress} | {speed_text} | "
            styled_prefix = (
                f"[{self.label}] {_color(progress, ANSI_CYAN, sys.stdout)} | {speed_text} | "
            )
        if len(plain_prefix) + 4 > width - 1:
            plain_prefix = f"[{self.label}] {progress} | "
            styled_prefix = f"[{self.label}] {_color(progress, ANSI_CYAN, sys.stdout)} | "

        path = self._display_path(len(plain_prefix))
        self.line.render(styled_prefix + path, plain_prefix + path, force=force)

    def finish(self, *, defer_flush: bool = False) -> None:
        self.line.finish(defer_flush=defer_flush)

@contextmanager
def windows_quick_edit_disabled():
    """Prevent classic Windows QuickEdit selection from pausing repair work."""
    if os.name != "nt":
        yield
        return

    state: tuple[object, int] | None = None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.argtypes = [ctypes.c_int32]
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.GetConsoleMode.restype = ctypes.c_int
        kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.SetConsoleMode.restype = ctypes.c_int
        handle = kernel32.GetStdHandle(-10)
        invalid = ctypes.c_void_p(-1).value
        if handle not in (None, 0, invalid):
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                previous = int(mode.value)
                quick_edit = 0x0040
                extended_flags = 0x0080
                updated = (previous | extended_flags) & ~quick_edit
                if kernel32.SetConsoleMode(handle, updated):
                    state = (handle, previous)
    except (AttributeError, OSError, TypeError, ValueError):
        state = None

    try:
        yield
    finally:
        if state is not None:
            handle, previous = state
            try:
                kernel32.SetConsoleMode(handle, previous)
            except (AttributeError, OSError, TypeError, ValueError):
                pass

class RepairArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print_error(message, file=sys.stderr)
        raise SystemExit(2)

MANIFEST_RE = re.compile(
    r"^B\.Cache\.(?P<kind>Windows|Dx11(?!_)|Dx12(?!_))"
    r"(?P<suffix>_[A-Za-z0-9]+)?\.bin!"
    r"(?P<type>[0-9A-Fa-f]+)_(?P<hash>[A-Za-z0-9+\-]+)$"
)

OPENWF_404_RE = re.compile(
    r"\bGET\s+(?P<path>/(?:0(?:_[A-Za-z0-9]+)?|9|A)/?\S*!"
    r"[0-9A-Fa-f]+_[A-Za-z0-9+\-]+)\s+404(?:\s|$)"
)
CDN_OBJECT_RE = re.compile(
    r"^/(?P<namespace>0(?:_[A-Za-z0-9]+)?|9|A)"
    r"(?P<logical>/[^!\r\n]+)!"
    r"(?P<type>[0-9A-Fa-f]+)_(?P<hash>[A-Za-z0-9+\-]+)$"
)
CONTENT_OBJECT_RE = re.compile(
    r"^(?P<namespace>0(?:_[A-Za-z0-9]+)?|9|A)"
    r"(?P<logical>/[^!\r\n]+)!"
    r"(?P<type>[0-9A-Fa-f]+)_(?P<hash>[A-Za-z0-9+\-]+)$"
)
PACKAGES_OBJECT_RE = re.compile(
    r"^Packages\.bin!(?P<type>[0-9A-Fa-f]+)_(?P<hash>[A-Za-z0-9+\-]+)$"
)
class RepairError(RuntimeError):
    pass

class UnsupportedManifestVersionError(RepairError):
    """The target B.Cache manifest uses a format version we have not validated."""

class PackagesAmbiguityError(RepairError):
    """Multiple integrity-valid captured Packages.bin objects are ambiguous."""

class UnsupportedPackagesVersionError(RepairError):
    """The one selected Packages.bin uses a format version we have not validated."""

class UnsupportedPackagesLayoutError(RepairError):
    """The one integrity-valid Packages.bin cannot be parsed by the validated layout."""

@dataclass(frozen=True, slots=True)
class TypePatternRow:
    type_id: int
    patterns: tuple[str, ...]
    note: str = ""

@dataclass(frozen=True, slots=True)
class ObservedObject:
    namespace: str
    logical_path: str
    type_id: int
    expected_hash: str
    path: Path

@dataclass(frozen=True, slots=True)
class ExeTypeTables:
    extension_rows: tuple[TypePatternRow, ...]
    native_types: dict[str, int]

def _load_optional_type_dependencies():
    try:
        import pefile  # type: ignore
        import capstone  # type: ignore
        from capstone import x86  # type: ignore
    except ImportError as exc:
        raise RepairError(
            "Warframe.x64.exe type extraction requires pefile and capstone. "
            "Install the bundled requirements.txt with: "
            "py -m pip install -r requirements.txt"
        ) from exc
    return pefile, capstone, x86

class _WarframeTypeExtractor:
    """Evaluate Warframe's cache-type getter functions without launching the game.

    This is adapted from the find_types.py/wfemu.py research implementation that
    preceded this standalone repairer. It intentionally implements only the small
    x86-64 instruction subset needed by the type getters and static type-registration
    code; see Warframe-Patch-Repair-Internals.md for provenance and scope.
    """

    PLATFORM_WINDOWS = 0
    SHADER_PLATFORMS = {0x9: "DX11 (Content/9)", 0xA: "DX12 (Content/A)"}
    EXT_SLOT = 22
    TYPE_SLOT = EXT_SLOT + 12

    def __init__(self, exe_path: Path):
        pefile, capstone, x86 = _load_optional_type_dependencies()
        self.capstone = capstone
        self.x86 = x86
        try:
            self.pe = pefile.PE(str(exe_path), fast_load=True)
        except Exception as exc:
            raise RepairError(f"Could not parse Warframe executable {exe_path}: {exc}") from exc

        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        try:
            self.text = next(s for s in self.pe.sections if s.Name.startswith(b".text"))
            self.rdata = next(s for s in self.pe.sections if s.Name.startswith(b".rdata"))
        except StopIteration as exc:
            raise RepairError("Warframe executable is missing .text or .rdata.") from exc

        self.tx = self.img[
            self.text.VirtualAddress:self.text.VirtualAddress + self.text.Misc_VirtualSize
        ]
        self.rdata_lo = self.rdata.VirtualAddress
        self.rd = self.img[
            self.rdata_lo:self.rdata_lo + self.rdata.Misc_VirtualSize
        ]
        self.m64 = (1 << 64) - 1
        self.full: dict[str, tuple[str, int]] = {}
        regs = [
            ("rax", "eax", "ax", "al"), ("rbx", "ebx", "bx", "bl"),
            ("rcx", "ecx", "cx", "cl"), ("rdx", "edx", "dx", "dl"),
            ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
            ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl"),
        ] + [(f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b") for i in range(8, 16)]
        for r64, r32, r16, r8 in regs:
            self.full[r64] = (r64, 64)
            self.full[r32] = (r64, 32)
            self.full[r16] = (r64, 16)
            self.full[r8] = (r64, 8)

    class Fail(Exception):
        pass

    def q(self, rva: int) -> int:
        return struct.unpack_from("<Q", self.img, rva)[0]

    def run(self, fn: int, dl: int, max_steps: int = 400, globals_: dict[int, int] | None = None) -> int:
        x86 = self.x86
        globals_ = globals_ or {}
        regs = {k: 0 for k in {v[0] for v in self.full.values()}}
        regs["rdx"] = dl
        regs["rsp"] = 0x10000
        stack: dict[int, int] = {}
        zf = cf = sf = of = False
        pc = fn
        ret_stack: list[int | None] = [None]
        steps = 0

        def rget(name: str) -> int:
            full, bits = self.full[name]
            return regs[full] & ((1 << bits) - 1)

        def rset(name: str, value: int) -> None:
            full, bits = self.full[name]
            value &= (1 << bits) - 1
            if bits in {32, 64}:
                regs[full] = value
            else:
                regs[full] = (regs[full] & ~((1 << bits) - 1) & self.m64) | value

        def addr(ins, operand):
            mem = operand.mem
            if mem.base == x86.X86_REG_RIP:
                return "img", ins.address + ins.size + mem.disp
            value = mem.disp
            if mem.base:
                value += regs[self.full[ins.reg_name(mem.base)][0]]
            if mem.index:
                value += regs[self.full[ins.reg_name(mem.index)][0]] * mem.scale
            return "stk", value & self.m64

        def get(ins, operand) -> int:
            if operand.type == x86.X86_OP_IMM:
                return operand.imm & ((1 << (operand.size * 8)) - 1)
            if operand.type == x86.X86_OP_REG:
                return rget(ins.reg_name(operand.reg))
            kind, value = addr(ins, operand)
            if (
                kind == "stk"
                and self.rdata.VirtualAddress <= value
                < self.rdata.VirtualAddress + self.rdata.Misc_VirtualSize
            ):
                kind = "img"
            if kind == "img" and value in globals_:
                return globals_[value] & ((1 << (operand.size * 8)) - 1)
            if kind == "img":
                if not (
                    self.rdata.VirtualAddress <= value
                    < self.rdata.VirtualAddress + self.rdata.Misc_VirtualSize
                ):
                    raise self.Fail(f"reads runtime global at {ins.address:#x}")
                return int.from_bytes(self.img[value:value + operand.size], "little")
            if value < 0x8000 or value > 0x20000:
                raise self.Fail(f"reads object field at {ins.address:#x}")
            return stack.get(value, 0) & ((1 << (operand.size * 8)) - 1)

        def put(ins, operand, value: int) -> None:
            if operand.type == x86.X86_OP_REG:
                rset(ins.reg_name(operand.reg), value)
                return
            kind, address = addr(ins, operand)
            if kind != "stk" or address < 0x8000 or address > 0x20000:
                raise self.Fail("store outside stack")
            stack[address] = value & ((1 << (operand.size * 8)) - 1)

        def cond(cc: str) -> bool:
            values = {
                "e": zf, "z": zf, "ne": not zf, "nz": not zf,
                "b": cf, "c": cf, "ae": not cf, "nc": not cf,
                "be": cf or zf, "a": not (cf or zf),
                "l": sf != of, "ge": sf == of, "le": zf or sf != of,
                "g": not zf and sf == of, "s": sf, "ns": not sf,
            }
            if cc not in values:
                raise self.Fail(f"unsupported condition {cc}")
            return values[cc]

        while True:
            steps += 1
            if steps > max_steps:
                raise self.Fail("steps")
            ins = next(self.md.disasm(self.img[pc:pc + 16], pc), None)
            if ins is None:
                raise self.Fail("decode")
            mnemonic, operands = ins.mnemonic, ins.operands
            nxt = pc + ins.size

            if mnemonic == "ret":
                return_to = ret_stack.pop()
                if return_to is None:
                    return regs["rax"] & 0xFFFF
                regs["rsp"] += 8
                pc = return_to
                continue
            if mnemonic == "call":
                if operands[0].type != x86.X86_OP_IMM:
                    raise self.Fail("indirect call")
                regs["rsp"] -= 8
                ret_stack.append(nxt)
                pc = operands[0].imm
                continue
            if mnemonic == "jmp":
                if operands[0].type != x86.X86_OP_IMM:
                    raise self.Fail("indirect jmp")
                pc = operands[0].imm
                continue
            if mnemonic.startswith("j"):
                pc = operands[0].imm if cond(mnemonic[1:]) else nxt
                continue
            if mnemonic == "push":
                regs["rsp"] -= 8
                stack[regs["rsp"]] = get(ins, operands[0])
                pc = nxt
                continue
            if mnemonic == "pop":
                put(ins, operands[0], stack.get(regs["rsp"], 0))
                regs["rsp"] += 8
                pc = nxt
                continue
            if mnemonic == "nop":
                pc = nxt
                continue
            if mnemonic in {"mov", "movzx"}:
                put(ins, operands[0], get(ins, operands[1]))
                pc = nxt
                continue
            if mnemonic == "movsx":
                value = get(ins, operands[1])
                bits = operands[1].size * 8
                if value >> (bits - 1):
                    value -= 1 << bits
                put(ins, operands[0], value)
                pc = nxt
                continue
            if mnemonic == "lea":
                _kind, value = addr(ins, operands[1])
                put(ins, operands[0], value)
                pc = nxt
                continue
            if mnemonic.startswith("cmov"):
                if cond(mnemonic[4:]):
                    put(ins, operands[0], get(ins, operands[1]))
                elif operands[0].size == 4:
                    put(ins, operands[0], get(ins, operands[0]))
                pc = nxt
                continue
            if mnemonic.startswith("set"):
                put(ins, operands[0], 1 if cond(mnemonic[3:]) else 0)
                pc = nxt
                continue
            if mnemonic in {
                "add", "sub", "cmp", "and", "or", "xor", "test", "inc",
                "dec", "shl", "shr", "imul", "neg",
            }:
                bits = operands[0].size * 8
                mask = (1 << bits) - 1
                a = get(ins, operands[0])
                b = get(ins, operands[1]) if len(operands) > 1 else (1 if mnemonic in {"inc", "dec"} else 0)
                if mnemonic in {"add", "inc"}:
                    result = a + b
                elif mnemonic in {"sub", "cmp", "dec"}:
                    result = a - b
                elif mnemonic in {"and", "test"}:
                    result = a & b
                elif mnemonic == "or":
                    result = a | b
                elif mnemonic == "xor":
                    result = a ^ b
                elif mnemonic == "shl":
                    result = a << b
                elif mnemonic == "shr":
                    result = a >> b
                elif mnemonic == "neg":
                    result = -a
                else:
                    result = a * (get(ins, operands[2]) if len(operands) > 2 else b)

                if mnemonic in {"sub", "cmp"}:
                    cf = a < b
                elif mnemonic == "add":
                    cf = result > mask
                else:
                    cf = False
                result &= mask
                zf = result == 0
                sf = bool(result >> (bits - 1))
                of = False
                if mnemonic not in {"cmp", "test"}:
                    put(ins, operands[0], result)
                pc = nxt
                continue
            raise self.Fail(f"{ins.address:#x} {mnemonic} {ins.op_str}")

    def ext_list(self, getter: int) -> list[str]:
        x86 = self.x86
        instructions = list(self.md.disasm(self.img[getter:getter + 8], getter))
        if not (
            len(instructions) >= 2
            and instructions[0].mnemonic == "lea"
            and instructions[1].mnemonic == "ret"
            and instructions[0].operands[1].mem.base == x86.X86_REG_RIP
        ):
            return []
        target = (
            instructions[0].address
            + instructions[0].size
            + instructions[0].operands[1].mem.disp
        )
        output: list[str] = []
        for index in range(16):
            pointer_rva = target + 8 * index
            if not (0 <= pointer_rva < len(self.img) - 8):
                break
            value = self.q(pointer_rva)
            if not value or not (0 < value - self.base < len(self.img)):
                break
            raw = self.img[value - self.base:value - self.base + 48].split(b"\0", 1)[0]
            if not raw or not all(32 <= byte < 127 for byte in raw):
                break
            output.append(raw.decode("ascii"))
        return output

    def runtime_global_of(self, error: str) -> int | None:
        match = re.search(r"reads runtime global at (0x[0-9a-f]+)", error)
        if not match:
            return None
        address = int(match.group(1), 16)
        ins = next(self.md.disasm(self.img[address:address + 16], address), None)
        if ins is None:
            return None
        for operand in ins.operands:
            if operand.type == self.x86.X86_OP_MEM and operand.mem.base == self.x86.X86_REG_RIP:
                return ins.address + ins.size + operand.mem.disp
        return None

    def run_with_globals(self, function: int, dl: int) -> int:
        globals_: dict[int, int] = {}
        for _ in range(8):
            try:
                return self.run(function, dl, globals_=globals_)
            except self.Fail as exc:
                global_rva = self.runtime_global_of(str(exc))
                if global_rva is None or global_rva in globals_:
                    raise
                globals_[global_rva] = 0
        raise self.Fail("too many globals")

    def extension_rows(self) -> tuple[TypePatternRow, ...]:
        rows: list[TypePatternRow] = []
        for match in re.finditer(rb"\x48\x8d\x05(....)\xc3", self.tx, re.S):
            getter = self.text.VirtualAddress + match.start()
            patterns = self.ext_list(getter)
            if not patterns or not all(
                re.fullmatch(r"[A-Za-z0-9_]*\.[A-Za-z0-9]{1,10}", pattern)
                for pattern in patterns
            ):
                continue
            pointer = self.rd.find(struct.pack("<Q", self.base + getter))
            while pointer != -1:
                slot = self.rdata_lo + pointer + 12 * 8
                if slot + 8 > len(self.img):
                    break
                function = self.q(slot) - self.base
                try:
                    windows_type = self.run(function, self.PLATFORM_WINDOWS)
                    try:
                        dl5_type = self.run(function, 5)
                    except self.Fail:
                        dl5_type = None
                    note = (
                        f"(dl=5: {dl5_type:X})"
                        if dl5_type is not None and dl5_type != windows_type
                        else ""
                    )
                    rows.append(TypePatternRow(windows_type, tuple(patterns), note))
                except self.Fail as exc:
                    if self.runtime_global_of(str(exc)) is not None:
                        for dl, name in self.SHADER_PLATFORMS.items():
                            try:
                                rows.append(
                                    TypePatternRow(
                                        self.run_with_globals(function, dl),
                                        tuple(patterns),
                                        name,
                                    )
                                )
                            except self.Fail:
                                pass
                pointer = self.rd.find(struct.pack("<Q", self.base + getter), pointer + 1)

        seen: set[tuple[int, tuple[str, ...], str]] = set()
        output: list[TypePatternRow] = []
        for row in rows:
            key = (row.type_id, row.patterns, row.note)
            if key not in seen:
                seen.add(key)
                output.append(row)
        output.sort(key=lambda row: (row.type_id, row.patterns, row.note))
        return tuple(output)

    def _section_of(self, target: int) -> str | None:
        for section in self.pe.sections:
            if section.VirtualAddress <= target < section.VirtualAddress + section.Misc_VirtualSize:
                return section.Name.rstrip(b"\0").decode("ascii", errors="replace")
        return None

    def _string_at(self, target: int) -> str | None:
        raw = self.img[target:target + 128].split(b"\0", 1)[0]
        if not raw or not all(32 <= byte < 127 for byte in raw):
            return None
        return raw.decode("ascii")

    def _rip_lea(self, ins) -> int | None:
        if (
            ins.mnemonic == "lea"
            and len(ins.operands) >= 2
            and ins.operands[1].type == self.x86.X86_OP_MEM
            and ins.operands[1].mem.base == self.x86.X86_REG_RIP
        ):
            return ins.address + ins.size + ins.operands[1].mem.disp
        return None

    def _function_starts(self) -> list[int]:
        try:
            pdata = next(section for section in self.pe.sections if section.Name.startswith(b".pdata"))
        except StopIteration as exc:
            raise RepairError("Warframe executable is missing .pdata.") from exc
        data = self.img[pdata.VirtualAddress:pdata.VirtualAddress + pdata.Misc_VirtualSize]
        starts = sorted(
            struct.unpack_from("<I", data, offset)[0]
            for offset in range(0, len(data) - 11, 12)
            if struct.unpack_from("<I", data, offset)[0]
        )
        if not starts:
            raise RepairError("Warframe executable has no usable .pdata function entries.")
        return starts

    def _find_register(self) -> int:
        package = self.img.find(b"\0/EE/Types/GraphicsRes/\0")
        if package < 0:
            raise RepairError("Could not locate the native-type registration package string.")
        package += 1
        votes: Counter[int] = Counter()
        for match in re.finditer(rb"\x48\x8d\x15(....)", self.tx, re.S):
            address = self.text.VirtualAddress + match.start()
            if address + 7 + struct.unpack("<i", match.group(1))[0] != package:
                continue
            calls = [
                ins.operands[0].imm
                for ins in self.md.disasm(self.img[address:address + 0x60], address)
                if ins.mnemonic == "call"
                and ins.operands[0].type == self.x86.X86_OP_IMM
            ]
            if len(calls) >= 2:
                votes[calls[1]] += 1
        if not votes:
            raise RepairError("Could not identify the native-type registration function.")
        return votes.most_common(1)[0][0]

    def _vtable_of(self, factory: int, depth: int = 0) -> int | None:
        last = None
        pending = None
        calls: list[int] = []
        for index, ins in enumerate(self.md.disasm(self.img[factory:factory + 800], factory)):
            target = self._rip_lea(ins)
            if target is not None:
                pending = (
                    (ins.reg_name(ins.operands[0].reg), target)
                    if self._section_of(target) == ".rdata"
                    else None
                )
            elif (
                ins.mnemonic == "mov"
                and pending
                and ins.operands[0].type == self.x86.X86_OP_MEM
                and ins.operands[0].mem.disp == 0
                and ins.operands[0].mem.index == 0
                and ins.operands[1].type == self.x86.X86_OP_REG
                and ins.reg_name(ins.operands[1].reg) == pending[0]
            ):
                last = pending[1]
            if ins.mnemonic == "call" and ins.operands[0].type == self.x86.X86_OP_IMM:
                calls.append(ins.operands[0].imm)
            if ins.mnemonic == "jmp" and ins.operands[0].type == self.x86.X86_OP_IMM and last is None and depth < 2:
                return self._vtable_of(ins.operands[0].imm, depth + 1)
            if ins.mnemonic in {"ret", "int3"} or index > 200:
                break
        if last is None and calls and depth < 2:
            return self._vtable_of(calls[0], depth + 1)
        return last

    def native_types(self) -> dict[str, int]:
        function_starts = self._function_starts()

        def fstart(address: int) -> int | None:
            index = bisect.bisect_right(function_starts, address) - 1
            return function_starts[index] if index >= 0 else None

        register = self._find_register()
        output: dict[str, int] = {}

        # The reference find_types.py used NumPy to vectorize this scan. A regex byte scan
        # keeps the repair package to pefile + capstone only while finding the same
        # direct E8 call sites.
        for match in re.finditer(rb"\xE8", self.tx):
            pos = match.start()
            if pos + 5 > len(self.tx):
                continue
            relative = struct.unpack_from("<i", self.tx, pos + 1)[0]
            site = self.text.VirtualAddress + pos
            if site + 5 + relative != register:
                continue

            function = fstart(site)
            if function is None:
                continue
            strings: list[str] = []
            text_targets: list[int] = []
            for ins in self.md.disasm(self.img[function:site], function):
                target = self._rip_lea(ins)
                if target is None:
                    continue
                section = self._section_of(target)
                if section == ".text":
                    text_targets.append(target)
                elif section == ".rdata":
                    value = self._string_at(target)
                    if value:
                        strings.append(value)

            package = next((value for value in strings[1:] if value.startswith("/")), None)
            if not strings or not package or not text_targets:
                continue
            path = package + strings[0]
            vtable = self._vtable_of(text_targets[-1])
            if vtable is None:
                continue
            slot = vtable + 8 * self.TYPE_SLOT
            if slot + 8 > len(self.img):
                continue
            function = self.q(slot) - self.base
            try:
                type_id = self.run(function, self.PLATFORM_WINDOWS)
            except self.Fail:
                # Platform-dependent native getters are not safe generic Content/0
                # mappings. The reference extractor records those separately for
                # shader namespaces; the repair resolver deliberately skips them.
                continue
            if type_id:
                output[path] = type_id
        return output

    def extract(self) -> ExeTypeTables:
        return ExeTypeTables(
            extension_rows=self.extension_rows(),
            native_types=self.native_types(),
        )

def extract_type_tables_from_exe(exe_path: Path) -> ExeTypeTables:
    """Extract type tables without letting optional EXE analysis abort repair.

    The evaluator follows reverse-engineered machine-code patterns that can change
    between Warframe builds. Expected extractor failures already use RepairError;
    unexpected parser/emulator exceptions are normalized here so callers can fall
    back to patch, Packages.bin, base and optional OpenWF evidence.
    """
    try:
        extractor = _WarframeTypeExtractor(exe_path)
        return extractor.extract()
    except RepairError:
        raise
    except Exception as exc:
        detail = _single_line_console_text(exc) or exc.__class__.__name__
        raise RepairError(
            f"Unexpected Warframe executable analysis failure for {exe_path}: {detail}"
        ) from exc

def find_warframe_exe(target_root: Path) -> Path | None:
    direct = target_root / "Warframe.x64.exe"
    return direct if direct.is_file() else None

@dataclass(frozen=True, slots=True)
class PatchTypeEvidence:
    exact_types: dict[tuple[str, str], int]
    parent_types: dict[tuple[str, str], int]
    pattern_types: dict[tuple[str, str], int]
    exact_objects: dict[tuple[str, str, str], ObservedObject]
    observations: int

def _namespace_group(namespace: str) -> str:
    return "0" if namespace.startswith("0") else namespace

class TypeResolver:
    def __init__(
        self,
        current_tables: ExeTypeTables | None,
        packages: PackagesParentIndex | None,
        patch_evidence: PatchTypeEvidence | None,
    ):
        self.current_tables = current_tables
        self.packages = packages
        self.patch_evidence = patch_evidence
        self._native_basename_map = (
            self._build_unique_native_basename_map(current_tables)
            if current_tables is not None
            else {}
        )

    @staticmethod
    def _build_unique_native_basename_map(
        tables: ExeTypeTables,
    ) -> dict[str, tuple[int, str]]:
        """Map an unqualified native class name to a type only when unambiguous.

        Packages.bin may encode a parent type relative to the asset's package
        directory (for example .../MissionDecks/.../MissionRewardItemManifest),
        while the executable's canonical native type path is
        /Lotus/Types/Game/MissionRewardItemManifest.  The terminal class name is
        the same.  Accept that normalization only when every executable mapping
        with that terminal name agrees on one CDN type ID.
        """
        grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for canonical_path, type_id in tables.native_types.items():
            basename = canonical_path.rsplit("/", 1)[-1].casefold()
            if basename:
                grouped[basename].append((type_id, canonical_path))

        result: dict[str, tuple[int, str]] = {}
        for basename, rows in grouped.items():
            type_ids = {type_id for type_id, _path in rows}
            if len(type_ids) != 1:
                continue
            type_id = next(iter(type_ids))
            canonical = sorted(path for _candidate, path in rows)[0]
            result[basename] = (type_id, canonical)
        return result

    def _native_type(
        self,
        logical_path: str,
        tables: ExeTypeTables | None,
        source_label: str,
    ) -> tuple[int, str] | None:
        if tables is None or self.packages is None:
            return None

        chain = _packages_parent_chain(logical_path, self.packages.parents)
        for parent in chain:
            type_id = tables.native_types.get(parent)
            if type_id is not None:
                return type_id, f"{source_label} native type {parent}"

        # If Packages.bin supplied a package-relative parent path, resolve its
        # terminal native class name against the executable.  This is not a
        # filename/path-family guess: Packages.bin provides the parent class and
        # the EXE provides the authoritative type mapping.  Ambiguous native
        # class names are deliberately rejected.
        # This resolver owns one matching-build EXE table, so a single prebuilt
        # basename map is sufficient; there is no need to key it by object identity.
        basename_map = self._native_basename_map
        for parent in chain:
            basename = parent.rsplit("/", 1)[-1].casefold()
            resolved = basename_map.get(basename)
            if resolved is None:
                continue
            type_id, canonical = resolved
            return (
                type_id,
                f"{source_label} unique native parent {parent.rsplit('/', 1)[-1]} "
                f"({canonical})",
            )

        return None

    def _pattern_type(
        self,
        logical_path: str,
        tables: ExeTypeTables | None,
        source_label: str,
        namespace: str,
    ) -> tuple[int, str] | None:
        if tables is None:
            return None
        lower = logical_path.lower()
        group = _namespace_group(namespace)
        matches: list[tuple[int, int, str]] = []
        for row in tables.extension_rows:
            if row.note.startswith("DX11") and group != "9":
                continue
            if row.note.startswith("DX12") and group != "A":
                continue
            if group == "0" and (row.note.startswith("DX11") or row.note.startswith("DX12")):
                continue
            for pattern in row.patterns:
                if lower.endswith(pattern.lower()):
                    matches.append((len(pattern), row.type_id, pattern))
        if not matches:
            return None

        best_len = max(length for length, _type_id, _pattern in matches)
        best = [(type_id, pattern) for length, type_id, pattern in matches if length == best_len]
        type_ids = {type_id for type_id, _pattern in best}
        if len(type_ids) != 1:
            return None
        type_id = next(iter(type_ids))
        patterns = sorted({pattern for candidate_type, pattern in best if candidate_type == type_id})
        return type_id, f"{source_label} filename pattern {patterns[0]}"

    def _resolve_from(
        self,
        logical_path: str,
        tables: ExeTypeTables | None,
        source_label: str,
        namespace: str,
    ) -> tuple[int | None, str | None]:
        if _namespace_group(namespace) == "0":
            native = self._native_type(logical_path, tables, source_label)
            if native is not None:
                return native
        pattern = self._pattern_type(logical_path, tables, source_label, namespace)
        if pattern is not None:
            return pattern
        return None, None

    def resolve_patch(
        self,
        namespace: str,
        logical_path: str,
    ) -> tuple[int | None, str | None]:
        evidence = self.patch_evidence
        if evidence is None:
            return None, None

        exact = evidence.exact_types.get((namespace, logical_path))
        if exact is not None:
            return exact, "existing patch object"

        group = _namespace_group(namespace)
        if self.packages is not None:
            for parent in _packages_parent_chain(logical_path, self.packages.parents):
                type_id = evidence.parent_types.get((group, parent))
                if type_id is not None:
                    return type_id, f"patch-local Packages.bin parent {parent}"

        lower = logical_path.lower()
        matches = [
            (len(pattern), type_id, pattern)
            for (pattern_group, pattern), type_id in evidence.pattern_types.items()
            if pattern_group == group and lower.endswith(pattern)
        ]
        if matches:
            best_len = max(length for length, _type_id, _pattern in matches)
            best = [(type_id, pattern) for length, type_id, pattern in matches if length == best_len]
            type_ids = {type_id for type_id, _pattern in best}
            if len(type_ids) == 1:
                type_id = next(iter(type_ids))
                pattern = sorted(pattern for candidate_type, pattern in best if candidate_type == type_id)[0]
                return type_id, f"patch-local filename pattern {pattern}"

        return None, None

    def resolve_current(
        self, logical_path: str, namespace: str
    ) -> tuple[int | None, str | None]:
        return self._resolve_from(logical_path, self.current_tables, "current EXE", namespace)

def scan_existing_content_objects(content_root: Path) -> list[ObservedObject]:
    observations: list[ObservedObject] = []
    progress = ActivityProgress("Scanning patch")
    try:
        for path in content_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(content_root).as_posix()
            except ValueError:
                continue
            match = CONTENT_OBJECT_RE.fullmatch(relative)
            if match is None:
                continue
            observations.append(
                ObservedObject(
                    namespace=match.group("namespace"),
                    logical_path=match.group("logical"),
                    type_id=int(match.group("type"), 16),
                    expected_hash=match.group("hash"),
                    path=path,
                )
            )
            if len(observations) == 1 or len(observations) % 128 == 0:
                progress.update(len(observations), detail=relative)
    except OSError as exc:
        raise RepairError(f"Could not scan existing OpenWF Content objects: {exc}") from exc
    finally:
        progress.finish()
    return observations

def _candidate_learning_patterns(
    current_tables: ExeTypeTables | None,
    observations: list[ObservedObject],
) -> set[str]:
    patterns: set[str] = set()
    if current_tables is not None:
        for row in current_tables.extension_rows:
            patterns.update(pattern.lower() for pattern in row.patterns if pattern)

    for observation in observations:
        if not observation.logical_path.startswith(("/Lotus/", "/EE/", "/Temp/")):
            continue
        suffix = PurePosixPath(observation.logical_path.lower()).suffix
        if suffix:
            patterns.add(suffix)
    return patterns

def build_patch_type_evidence(
    observations: list[ObservedObject],
    packages: PackagesParentIndex | None,
    current_tables: ExeTypeTables | None,
) -> PatchTypeEvidence:
    exact_counts: dict[tuple[str, str], Counter[int]] = defaultdict(Counter)
    parent_counts: dict[tuple[str, str], Counter[int]] = defaultdict(Counter)
    pattern_counts: dict[tuple[str, str], Counter[int]] = defaultdict(Counter)
    exact_object_candidates: dict[
        tuple[str, str, str], dict[int, ObservedObject]
    ] = defaultdict(dict)
    patterns = _candidate_learning_patterns(current_tables, observations)

    progress = ActivityProgress("Building type evidence", len(observations))
    try:
        for index, observation in enumerate(observations, 1):
            exact_counts[(observation.namespace, observation.logical_path)][observation.type_id] += 1
            exact_object_candidates[
                (observation.namespace, observation.logical_path, observation.expected_hash)
            ].setdefault(observation.type_id, observation)

            if observation.logical_path.startswith(("/Lotus/", "/EE/", "/Temp/")):
                group = _namespace_group(observation.namespace)
                if packages is not None:
                    for parent in _packages_parent_chain(observation.logical_path, packages.parents):
                        parent_counts[(group, parent)][observation.type_id] += 1

                lower = observation.logical_path.lower()
                for pattern in patterns:
                    if lower.endswith(pattern):
                        pattern_counts[(group, pattern)][observation.type_id] += 1

            if index == 1 or index % 64 == 0 or index == len(observations):
                progress.update(index, detail=observation.logical_path)
    finally:
        progress.finish()

    exact_types = {
        key: next(iter(counter))
        for key, counter in exact_counts.items()
        if len(counter) == 1
    }
    parent_types = {
        key: next(iter(counter))
        for key, counter in parent_counts.items()
        if len(counter) == 1
    }
    pattern_types = {
        key: next(iter(counter))
        for key, counter in pattern_counts.items()
        if len(counter) == 1
    }
    exact_objects = {
        key: next(iter(by_type.values()))
        for key, by_type in exact_object_candidates.items()
        if len(by_type) == 1
    }

    return PatchTypeEvidence(
        exact_types=exact_types,
        parent_types=parent_types,
        pattern_types=pattern_types,
        exact_objects=exact_objects,
        observations=len(observations),
    )

def build_type_resolver(
    target_root: Path,
    packages: PackagesParentIndex | None,
    observations: list[ObservedObject],
    *,
    patch_types_only: bool = False,
) -> TypeResolver:
    current_tables: ExeTypeTables | None = None

    exe_path = find_warframe_exe(target_root)
    if exe_path is not None:
        try:
            print(f"[Types] Extracting current-build cache type mappings from: {exe_path}")
            current_tables = extract_type_tables_from_exe(exe_path)
            print(
                f"[Types] Current EXE mappings: {len(current_tables.extension_rows)} "
                f"filename {_plural(len(current_tables.extension_rows), 'rule')}, "
                f"{len(current_tables.native_types)} native cached "
                f"{_plural(len(current_tables.native_types), 'type')}"
            )
        except RepairError as exc:
            print_warning(
                f"Automatic EXE type extraction unavailable: {exc}",
                prefix="[Types]",
            )
    else:
        print_warning(
            "Warframe.x64.exe was not found; current-build EXE type extraction is unavailable.",
            prefix="[Types]",
        )

    patch_evidence = build_patch_type_evidence(
        observations,
        packages,
        current_tables,
    )
    print(
        f"[Types] Patch-local evidence: {patch_evidence.observations} observed "
        f"{_plural(patch_evidence.observations, 'object')}, "
        f"{len(patch_evidence.exact_types)} exact path "
        f"{_plural(len(patch_evidence.exact_types), 'mapping')}, "
        f"{len(patch_evidence.parent_types)} unambiguous parent "
        f"{_plural(len(patch_evidence.parent_types), 'mapping')}, "
        f"{len(patch_evidence.pattern_types)} unambiguous filename "
        f"{_plural(len(patch_evidence.pattern_types), 'pattern')}"
    )

    if current_tables is None:
        if patch_types_only:
            print(
                "[Types] Current EXE mappings are unavailable; patch-local evidence remains available."
            )
        else:
            print(
                "[Types] Current EXE mappings are unavailable; patch-local evidence and "
                "base Cache.Windows type hints remain available."
            )

    return TypeResolver(current_tables, packages, patch_evidence)

def b64m_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=").replace("/", "-")

def cache_name(
    path: str, type_id: int, b64m_hash: str, namespace: str = "0"
) -> str:
    return f"{namespace}{path}!{type_id:X}_{b64m_hash}"

def cdn_url(name: str) -> str:
    # Keep path separators and the CDN's "!" delimiter. "+" in the modified
    # base64 hash must be percent-encoded so it is not treated as a space.
    return CDN_BASE + urllib.parse.quote(name, safe="/!_-.,~")

def local_path(root: Path, name: str) -> Path:
    posix = PurePosixPath(name)
    if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
        raise RepairError(f"Unsafe CDN path generated: {name}")
    return _validate_windows_output_path(
        root.joinpath(*posix.parts),
        label="Output asset path",
    )

def bundled_oodle_path() -> Path:
    return Path(__file__).resolve().parent / OODLE_DLL_NAME

class Oodle:
    def __init__(self):
        self._library = None
        self._path: Path | None = None

    @property
    def path(self) -> Path | None:
        return self._path

    @staticmethod
    def _try_load(path: Path):
        library = ctypes.CDLL(str(path))
        function = library.OodleLZ_Decompress
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        function.restype = ctypes.c_ssize_t
        return library

    def _load(self):
        if self._library is not None:
            return self._library

        path = bundled_oodle_path()
        if not path.is_file():
            raise RepairError(
                "Bundled Oodle runtime is missing: "
                f"{path}. Re-extract the complete repair-tool archive; "
                "the tool does not download Oodle at runtime."
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RepairError(f"Could not read bundled Oodle runtime {path}: {exc}") from exc

        if len(data) != OODLE_X64_SIZE:
            raise RepairError(
                "Bundled Oodle runtime has the wrong size: "
                f"{len(data)} bytes instead of {OODLE_X64_SIZE}: {path}"
            )

        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != OODLE_X64_SHA256:
            raise RepairError(
                "Bundled Oodle runtime failed SHA-256 verification: "
                f"{actual_sha256}: {path}"
            )

        try:
            library = self._try_load(path)
        except (AttributeError, OSError) as exc:
            raise RepairError(
                f"Could not load bundled Oodle runtime {path}: {exc}"
            ) from exc

        self._library = library
        self._path = path
        return library

    def _decompress_call(
        self,
        compressed: bytes | bytearray,
        output_size: int,
    ) -> tuple[bytes, int]:
        library = self._load()
        function = library.OodleLZ_Decompress

        if not isinstance(compressed, bytes):
            compressed = bytes(compressed)
        source = ctypes.create_string_buffer(compressed, len(compressed))
        destination = ctypes.create_string_buffer(output_size)
        result = int(
            function(
                ctypes.cast(source, ctypes.c_void_p),
                len(compressed),
                ctypes.cast(destination, ctypes.c_void_p),
                output_size,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
            )
        )
        return destination.raw, result

    def decompress(self, compressed: bytes | bytearray, expected_size: int) -> bytes:
        raw, result = self._decompress_call(compressed, expected_size)
        if result != expected_size:
            raise RepairError(
                f"Oodle decompression returned {result} bytes; expected {expected_size}."
            )
        return raw[:expected_size]

def _chunk_header(
    data: bytes | bytearray,
    offset: int,
) -> tuple[int, int, int, int, int]:
    if offset + 9 > len(data):
        raise RepairError("Truncated SHCC chunk header.")
    chunk_type = data[offset]
    decompressed_size, compressed_size = struct.unpack_from("<II", data, offset + 1)
    payload_start = offset + 9
    payload_end = payload_start + compressed_size
    if payload_end > len(data):
        raise RepairError("Truncated SHCC chunk payload.")
    return chunk_type, decompressed_size, compressed_size, payload_start, payload_end

def _decompress_oodle_payload(
    payload: bytes | bytearray,
    expected_size: int,
    oodle: Oodle,
) -> bytes:
    output = bytearray()
    offset = 0

    while len(output) < expected_size:
        if offset + 8 > len(payload):
            raise RepairError("Truncated Oodle block header.")

        block_info = payload[offset:offset + 8]
        offset += 8

        if block_info[0] != 0x80 or (block_info[7] & 0x0F) != 0x01:
            raise RepairError("Unexpected Oodle block header.")

        num1 = int.from_bytes(block_info[:4], "big")
        num2 = int.from_bytes(block_info[4:], "big")
        compressed_size = (num1 >> 2) & 0xFFFFFF
        decompressed_size = (num2 >> 5) & 0xFFFFFF

        if compressed_size <= 0 or decompressed_size <= 0:
            raise RepairError("Invalid Oodle block size.")
        if offset + compressed_size > len(payload):
            raise RepairError("Truncated Oodle block.")
        block = payload[offset:offset + compressed_size]
        offset += compressed_size

        if not block or block[0] != 0x8C:
            raise RepairError("Unexpected Oodle block data.")

        output.extend(oodle.decompress(block, decompressed_size))

    if len(output) != expected_size:
        raise RepairError(
            f"Oodle chunk produced {len(output)} bytes; expected {expected_size}."
        )
    if offset != len(payload):
        remaining = len(payload) - offset
        suffix = "byte" if remaining == 1 else "bytes"
        raise RepairError(
            f"Unexpected {remaining} trailing {suffix} in Oodle chunk payload."
        )
    return bytes(output)

def _decode_chunk(
    data: bytes | bytearray,
    offset: int,
    oodle: Oodle,
) -> tuple[bytes | bytearray, int]:
    chunk_type, decompressed_size, compressed_size, start, end = _chunk_header(data, offset)
    payload = data[start:end]

    if chunk_type == 0:
        if compressed_size != decompressed_size:
            raise RepairError("Invalid uncompressed SHCC chunk sizes.")
        return payload, end
    if chunk_type == 2:
        return _decompress_oodle_payload(payload, decompressed_size, oodle), end

    raise RepairError(f"Unsupported SHCC chunk type: {chunk_type}")

SHCC_PREAMBLE = b"SHCC\x1F\x00\x00\x00"

def _unwrap_outer_compressed_shcc(
    data: bytes | bytearray,
    oodle: Oodle,
    *,
    progress_name: str | None = None,
) -> bytes:
    """Verify and unwrap the observed whole-object SHCC wrapper form.

    Observed B7 HDR and 8B WAV CDN samples store a raw-size field in the four bytes
    immediately before the 0x43 wrapper marker, followed by the wrapper CRC32C.
    Inner decompression remains strict; failures are reported with their exact
    verification stage.
    """
    if len(data) < 13 or data[-5] != 0x43:
        raise RepairError("Invalid outer-compressed SHCC footer.")
    expected_crc = struct.unpack_from("<I", data, len(data) - 4)[0]
    actual_crc = crc32c(data, end=len(data) - 4, progress_name=progress_name)
    if actual_crc != expected_crc:
        raise RepairError(
            f"Outer SHCC CRC32C mismatch: expected 0x{expected_crc:08X}, got 0x{actual_crc:08X}."
        )
    raw_size = struct.unpack_from("<I", data, len(data) - 9)[0]
    if raw_size < len(SHCC_PREAMBLE):
        raise RepairError(f"Invalid outer-compressed SHCC raw size: {raw_size}.")
    inner = oodle.decompress(data[:-9], raw_size)
    if not inner.startswith(SHCC_PREAMBLE):
        raise RepairError("Outer-compressed object did not unwrap to SHCC.")
    return inner

def shcc_header_and_hash(
    data: bytes | bytearray,
    oodle: Oodle,
    *,
    progress_name: str | None = None,
    verify_container_crc: bool = True,
) -> tuple[bytes, bytes]:
    if len(data) < 17 or data[:8] != SHCC_PREAMBLE:
        raise RepairError("Not an SHCC object.")

    if verify_container_crc:
        # Direct SHCC objects use the ordinary 0x52 footer marker followed by
        # CRC32C. The separate observed 0x43 whole-object wrapper is handled
        # before this function and intentionally skips a second inner footer.
        if data[-5] != 0x52:
            raise RepairError(
                f"Invalid SHCC footer marker: expected 0x52, got 0x{data[-5]:02X}."
            )
        expected_crc = struct.unpack_from("<I", data, len(data) - 4)[0]
        actual_crc = crc32c(data, end=len(data) - 4, progress_name=progress_name)
        if actual_crc != expected_crc:
            raise RepairError(
                f"SHCC CRC32C mismatch: expected 0x{expected_crc:08X}, got 0x{actual_crc:08X}."
            )

    header, _next_offset = _decode_chunk(data, 8, oodle)
    if len(header) < 16:
        raise RepairError("SHCC header chunk is too short.")
    return header, header[:16]

def validate_shcc(
    data: bytes | bytearray,
    expected_b64m_hash: str,
    oodle: Oodle,
    *,
    progress_name: str | None = None,
) -> None:
    outer_wrapped = not data.startswith(SHCC_PREAMBLE)
    if outer_wrapped:
        inner = _unwrap_outer_compressed_shcc(
            data,
            oodle,
            progress_name=progress_name,
        )
    else:
        inner = data

    # The observed 0x43 whole-object wrapper has its own CRC32C. Its decompressed
    # SHCC representation is not guaranteed to carry a second normal SHCC footer,
    # so validate the outer CRC plus the exact embedded manifest hash instead of
    # misreading trailing inner payload bytes as another CRC.
    _header, digest = shcc_header_and_hash(
        inner,
        oodle,
        progress_name=progress_name,
        verify_container_crc=not outer_wrapped,
    )
    actual_hash = b64m_encode(digest)
    if actual_hash != expected_b64m_hash:
        raise RepairError(
            f"SHCC hash mismatch: expected {expected_b64m_hash}, got {actual_hash}."
        )

def verify_shcc(
    data: bytes | bytearray,
    expected_b64m_hash: str,
    oodle: Oodle,
    *,
    progress_name: str | None = None,
) -> bool:
    try:
        validate_shcc(
            data,
            expected_b64m_hash,
            oodle,
            progress_name=progress_name,
        )
    except RepairError:
        return False
    return True

MANIFEST_SECTION_NAMES = ("service", "packed", "stripped")

def _manifest_header_version(header: bytes) -> int:
    if len(header) < 20:
        raise RepairError("Cache manifest header is too short.")
    return struct.unpack_from("<I", header, 16)[0]

def parse_manifest_header(header: bytes):
    # U44 Cache.bin/B.Cache manifest structure:
    #   GUID[16], u32 version, then service/packed/stripped sections.
    # Every entry stores path, 16-byte target hash and a packed u32 where the
    # low 24 bits are size and the high 8 bits are flags.
    #
    # All 38 directly decompressed U44.0.1/U44.0.2 manifests use version 14.
    # Treat a different value as a compatibility boundary instead of attempting
    # to interpret a future layout merely because its opening bytes still fit.
    version = _manifest_header_version(header)
    if version != SUPPORTED_MANIFEST_VERSION:
        raise UnsupportedManifestVersionError(
            f"Unsupported cache-manifest version {version}; "
            f"this repairer is validated for version {SUPPORTED_MANIFEST_VERSION}."
        )
    offset = 20

    for section in MANIFEST_SECTION_NAMES:
        if offset + 4 > len(header):
            raise RepairError(f"Truncated cache-manifest {section} section count.")
        count = struct.unpack_from("<I", header, offset)[0]
        offset += 4

        if count > 5_000_000:
            raise RepairError(
                f"Unreasonable cache-manifest {section} entry count: {count}."
            )

        for _ in range(count):
            if offset + 4 > len(header):
                raise RepairError("Truncated cache-manifest path length.")
            path_size = struct.unpack_from("<I", header, offset)[0]
            offset += 4

            required = path_size + 20
            if path_size <= 0 or offset + required > len(header):
                raise RepairError("Truncated cache-manifest entry.")

            raw_path = header[offset:offset + path_size]
            offset += path_size
            manifest_hash = header[offset:offset + 16]
            offset += 16
            # Packed size/flags metadata is not needed for repair selection.
            offset += 4

            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                path = raw_path.decode("latin-1")

            yield section, path, manifest_hash

    trailing = header[offset:]
    if trailing:
        raise RepairError(
            f"Unexpected {len(trailing)} trailing {_plural(len(trailing), 'byte')} in cache manifest."
        )

def manifest_files(content_root: Path) -> list[tuple[Path, re.Match[str]]]:
    directory = content_root / "0"
    if not directory.is_dir():
        return []

    found: list[tuple[Path, re.Match[str]]] = []
    identities: dict[tuple[str, str], Path] = {}
    try:
        children = sorted(directory.iterdir(), key=lambda p: p.name.casefold())
    except OSError as exc:
        raise RepairError(f"Could not enumerate {directory}: {exc}") from exc

    for path in children:
        if not path.is_file():
            continue
        match = MANIFEST_RE.fullmatch(path.name)
        if match is None:
            continue

        identity = (match.group("kind"), match.group("suffix"))
        previous = identities.get(identity)
        if previous is not None:
            raise RepairError(
                "Multiple target manifests were found for the same cache family: "
                f"{previous.name} and {path.name}. Remove stale manifests from older "
                "target builds before repairing this patch."
            )

        identities[identity] = path
        found.append((path, match))
    return found

def resolve_content_root(target_root: Path) -> Path:
    candidates = (
        target_root / "OpenWF" / "Content",
        target_root / "OpenWF",
        target_root / "Content",
        target_root,
    )

    for candidate in candidates:
        if manifest_files(candidate):
            return candidate

    expected = target_root / "OpenWF" / "Content" / "0"
    raise RepairError(
        "Could not find any B.Cache manifest objects in a supported patch layout. "
        f"Expected them below something like: {expected}"
    )

def _read_response_with_progress(response, display_name: str) -> bytearray:
    expected_header = response.headers.get("Content-Length")
    expected_size: int | None = None
    if expected_header is not None:
        try:
            expected_size = int(expected_header)
        except ValueError:
            expected_size = None

    progress = DownloadProgress(display_name, expected_size)
    body = bytearray()
    try:
        while True:
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            body.extend(chunk)
            progress.update(len(chunk))
        progress.update(0, force=True)
    finally:
        progress.finish()

    if expected_size is not None and len(body) != expected_size:
        raise OSError(
            f"incomplete response: expected {expected_size} bytes, received {len(body)}"
        )
    return body

def download_asset(
    url: str,
    *,
    display_name: str,
    expected_hash: str,
    oodle: Oodle,
) -> tuple[bytes | bytearray | None, str | None, int | None]:
    last_error: str | None = None
    last_status: int | None = None

    for attempt in range(1, HTTP_ATTEMPTS + 1):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                status = int(getattr(response, "status", 0) or 0)
                last_status = status
                if status != 200:
                    last_error = f"HTTP {status}"
                    if status not in {408, 425, 429, 500, 502, 503, 504}:
                        break
                else:
                    body = _read_response_with_progress(response, display_name)
                    try:
                        validate_shcc(
                            body,
                            expected_hash,
                            oodle,
                            progress_name=display_name,
                        )
                    except RepairError as exc:
                        last_error = f"verification failed: {_single_line_console_text(exc)}"
                    else:
                        return body, None, 200
                    # A successful HTTP response can still be truncated/corrupted in a
                    # way Content-Length does not expose. Retry the exact object before
                    # declaring repair failure.

        except urllib.error.HTTPError as exc:
            last_status = exc.code
            last_error = f"HTTP {exc.code}"
            if exc.code not in {408, 425, 429, 500, 502, 503, 504}:
                break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_status = None
            last_error = _single_line_console_text(exc)

        if attempt < HTTP_ATTEMPTS:
            print_retry(attempt + 1, last_error or "unknown download error", display_name)
            time.sleep(0.5 * attempt)

    return None, last_error or "unknown download error", last_status

def atomic_write(
    path: Path,
    data: bytes | bytearray,
    *,
    progress_label: str = "Saving",
    display_name: str | None = None,
) -> None:
    display = display_name or path.name
    _validate_windows_output_path(path, label="Output asset path")
    _ensure_directory_with_disk_wait(path.parent, display)

    # Keep enough free space for the complete same-volume temporary file plus a
    # small safety reserve. Waiting happens before the write and also after a real
    # ENOSPC/Windows disk-full error, so the already-verified in-memory asset can
    # be retried without another download.
    _wait_for_disk_space(path.parent, len(data), display)

    while True:
        temporary: Path | None = None
        progress: DownloadProgress | None = None
        try:
            try:
                fd, temp_name = tempfile.mkstemp(
                    prefix=".wfpr-",
                    suffix=".tmp",
                    dir=path.parent,
                )
            except OSError as exc:
                if not _is_disk_full_error(exc):
                    raise
                _wait_for_disk_space(path.parent, len(data), display)
                continue

            temporary = Path(temp_name)
            try:
                _validate_windows_output_path(
                    temporary,
                    label="Temporary output path",
                )
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
                temporary = None
                raise
            progress = DownloadProgress(
                display,
                len(data),
                label=progress_label,
                # Do not flash a transient row for tiny writes that complete immediately.
                show_after=0.15,
            )
            try:
                with os.fdopen(fd, "wb") as handle:
                    view = memoryview(data)
                    for offset in range(0, len(view), 1024 * 1024):
                        chunk = view[offset:offset + 1024 * 1024]
                        written = handle.write(chunk)
                        if written != len(chunk):
                            raise OSError(
                                f"short write: expected {len(chunk)} bytes, wrote {written}"
                            )
                        progress.update(written)
            except BaseException:
                # os.fdopen owns the descriptor once entered; if construction or
                # the write failed before that point, close the raw descriptor too.
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise

            progress.update(0, force=True)

            while True:
                try:
                    os.replace(temporary, path)
                    temporary = None
                    if progress is not None:
                        progress.finish(defer_flush=True)
                    return
                except OSError as exc:
                    if not _is_disk_full_error(exc):
                        raise
                    if progress is not None:
                        progress.finish()
                        progress = None
                    _wait_for_disk_space(path.parent, 0, display)
        except OSError as exc:
            if progress is not None:
                progress.finish()
                progress = None
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            if not _is_disk_full_error(exc):
                raise
            _wait_for_disk_space(path.parent, len(data), display)
            continue
        finally:
            if progress is not None:
                progress.finish()
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

TOC_MAGIC = 0x1867C64E
TOC_VERSIONS = {16, 20}
TOC_ENTRY = struct.Struct("<qqiiii64s")

@dataclass(frozen=True, slots=True)
class CacheEntry:
    cache_path: Path
    logical_path: str
    offset: int
    compressed_len: int
    length: int

@dataclass(frozen=True, slots=True)
class ManifestAsset:
    namespace: str
    section: str
    logical_path: str
    manifest_hash: bytes

    @property
    def hash_b64(self) -> str:
        return b64m_encode(self.manifest_hash)

def _decode_toc_name(raw: bytes) -> str:
    raw = raw.split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")

def iter_toc_entries(toc_path: Path):
    try:
        data = toc_path.read_bytes()
    except OSError as exc:
        raise RepairError(f"Could not read {toc_path}: {exc}") from exc

    if len(data) < 8 or (len(data) - 8) % TOC_ENTRY.size != 0:
        raise RepairError(f"Unexpected TOC size: {toc_path}")

    magic, version = struct.unpack_from("<II", data, 0)
    if magic != TOC_MAGIC or version not in TOC_VERSIONS:
        raise RepairError(
            f"Unsupported TOC header in {toc_path.name}: "
            f"magic=0x{magic:08X}, version={version}"
        )

    directories: list[str] = [""]
    cache_path = toc_path.with_suffix(".cache")

    offset = 8
    while offset < len(data):
        (
            cache_offset,
            timestamp,
            compressed_len,
            length,
            _reserved,
            parent_dir_index,
            raw_name,
        ) = TOC_ENTRY.unpack_from(data, offset)
        offset += TOC_ENTRY.size

        name = _decode_toc_name(raw_name)
        if not name:
            continue
        if parent_dir_index < 0 or parent_dir_index >= len(directories):
            raise RepairError(
                f"Invalid parent directory index {parent_dir_index} in {toc_path.name}"
            )

        parent = directories[parent_dir_index]
        logical_path = f"{parent}/{name}" if parent else f"/{name}"

        if cache_offset == -1:
            directories.append(logical_path)
            continue

        if timestamp == 0:
            # LotusLib treats this as a deleted/duplicate TOC entry.
            continue

        yield CacheEntry(
            cache_path=cache_path,
            logical_path=logical_path,
            offset=cache_offset,
            compressed_len=compressed_len,
            length=length,
        )

def find_cache_windows_dir(target_root: Path) -> Path | None:
    direct = target_root / "Cache.Windows"
    if direct.is_dir():
        return direct

    # Accept pointing directly at Cache.Windows too.
    if target_root.name.casefold() == "cache.windows" and target_root.is_dir():
        return target_root

    # Keep this bounded. The normal installation has Cache.Windows at root.
    try:
        for child in target_root.iterdir():
            if child.is_dir() and child.name.casefold() == "cache.windows":
                return child
    except OSError as exc:
        raise RepairError(f"Could not enumerate {target_root} while locating Cache.Windows: {exc}") from exc
    return None

def _warframe_block_lens(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        return 0, 0

    info = data[offset:offset + 8]
    if info[0] != 0x80 or (info[7] & 0x0F) != 0x01:
        return 0, 0

    num1 = int.from_bytes(info[:4], "big")
    num2 = int.from_bytes(info[4:], "big")
    compressed_len = (num1 >> 2) & 0xFFFFFF
    decompressed_len = (num2 >> 5) & 0xFFFFFF
    return compressed_len, decompressed_len

def lzf_decompress(data: bytes, expected_size: int) -> bytes:
    output = bytearray()
    i = 0

    while i < len(data):
        control = data[i]
        i += 1

        if control < 32:
            literal_len = control + 1
            if i + literal_len > len(data):
                raise RepairError("Truncated LZF literal run.")
            output.extend(data[i:i + literal_len])
            i += literal_len
            continue

        length = control >> 5
        reference_offset = (control & 0x1F) << 8

        if length == 7:
            if i >= len(data):
                raise RepairError("Truncated LZF length.")
            length += data[i]
            i += 1

        if i >= len(data):
            raise RepairError("Truncated LZF back-reference.")
        reference_offset += data[i]
        i += 1

        reference = len(output) - reference_offset - 1
        if reference < 0:
            raise RepairError("Invalid LZF back-reference.")

        length += 2
        for _ in range(length):
            if reference < 0 or reference >= len(output):
                raise RepairError("Invalid LZF copy range.")
            output.append(output[reference])
            reference += 1

    if len(output) != expected_size:
        raise RepairError(
            f"LZF produced {len(output)} bytes; expected {expected_size}."
        )
    return bytes(output)

def read_cache_entry_raw(entry: CacheEntry) -> bytes:
    if not entry.cache_path.is_file():
        raise RepairError(f"Matching cache file is missing: {entry.cache_path}")

    try:
        with entry.cache_path.open("rb") as file:
            file.seek(entry.offset)
            data = file.read(entry.compressed_len)
    except OSError as exc:
        raise RepairError(f"Could not read {entry.cache_path}: {exc}") from exc

    if len(data) != entry.compressed_len:
        raise RepairError(
            f"Short read from {entry.cache_path.name}: "
            f"{len(data)} of {entry.compressed_len} bytes."
        )
    return data

def decompress_cache_entry(entry: CacheEntry, oodle: Oodle) -> bytes:
    raw = read_cache_entry_raw(entry)
    if entry.compressed_len == entry.length:
        return raw

    output = bytearray()
    pos = 0

    while len(output) < entry.length:
        compressed_len, decompressed_len = _warframe_block_lens(raw, pos)

        if compressed_len == 0 and decompressed_len == 0:
            # LotusLib falls back to treating the whole entry as one block.
            compressed_len = entry.compressed_len
            decompressed_len = entry.length
            block_start = 0
            pos = len(raw)
        else:
            block_start = pos + 8
            block_end = block_start + compressed_len
            if block_end > len(raw):
                raise RepairError("Truncated Cache.Windows compressed block.")
            pos = block_end

        block = raw[block_start:block_start + compressed_len]
        if not block:
            raise RepairError("Empty Cache.Windows compressed block.")

        # Equal framed block sizes mean the block is stored raw.
        if compressed_len == decompressed_len:
            decompressed = bytes(block)
        elif block[0] == 0x8C:
            decompressed = oodle.decompress(block, decompressed_len)
        else:
            # Custom LZ/LZF-compatible fallback retained for cache compatibility.
            # Do not infer a historical cutoff from this branch; compression
            # behavior must be established from real fixtures.
            decompressed = lzf_decompress(block, decompressed_len)

        output.extend(decompressed)

        if compressed_len == entry.compressed_len and block_start == 0:
            break

    if len(output) != entry.length:
        raise RepairError(
            f"Cache.Windows entry produced {len(output)} bytes; expected {entry.length}."
        )
    return bytes(output)

def parse_common_header(data: bytes) -> tuple[bytes, int]:
    if len(data) < 24:
        raise RepairError("CommonHeader is too short.")

    header_hash = data[:16]
    offset = 16

    source_path_count = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if source_path_count > 3000:
        raise RepairError(f"Unreasonable CommonHeader source path count: {source_path_count}")

    for _ in range(source_path_count):
        if offset + 4 > len(data):
            raise RepairError("Truncated CommonHeader source-path length.")
        path_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if path_len > 200 or offset + path_len > len(data):
            raise RepairError("Invalid CommonHeader source path.")
        offset += path_len

    if offset + 4 > len(data):
        raise RepairError("Truncated CommonHeader attribute length.")
    attribute_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if offset + attribute_len > len(data):
        raise RepairError("Truncated CommonHeader attributes.")
    offset += attribute_len

    if attribute_len > 0:
        if offset >= len(data):
            raise RepairError("Truncated CommonHeader attribute terminator.")
        offset += 1

    if offset + 4 > len(data):
        raise RepairError("Truncated CommonHeader type.")
    type_id = struct.unpack_from("<I", data, offset)[0] & 0xFFFF
    return header_hash, type_id

def _make_crc32c_table() -> tuple[int, ...]:
    polynomial = 0x82F63B78
    table: list[int] = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ (polynomial if (crc & 1) else 0)
        table.append(crc)
    return tuple(table)

CRC32C_TABLE = _make_crc32c_table()

def crc32c(
    data: bytes | bytearray,
    *,
    end: int | None = None,
    progress_name: str | None = None,
) -> int:
    limit = len(data) if end is None else max(0, min(len(data), end))
    progress = (
        DownloadProgress(
            progress_name,
            limit,
            label="Verifying",
            show_after=0.25,
        )
        if progress_name is not None and limit >= VERIFY_PROGRESS_MIN_BYTES
        else None
    )
    crc = 0xFFFFFFFF
    try:
        for start in range(0, limit, 1024 * 1024):
            stop = min(limit, start + 1024 * 1024)
            for byte in data[start:stop]:
                crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
            if progress is not None:
                progress.update(stop - start)
    finally:
        if progress is not None:
            progress.finish()
    return (~crc) & 0xFFFFFFFF

def _cache_namespace_from_package(package: str) -> str:
    lower = package.casefold()
    if lower.endswith("dx11"):
        return "9"
    if lower.endswith("dx12"):
        return "A"
    language = re.search(r"(_[a-z]{2,3})$", lower)
    if language is not None:
        return "0" + language.group(1)
    return "0"

class BaseHeaderCache:
    def __init__(
        self,
        cache_dir: Path,
        target_keys: set[tuple[str, str]],
        oodle: Oodle,
    ):
        self.cache_dir = cache_dir
        self.oodle = oodle
        self.entries: dict[tuple[str, str], list[CacheEntry]] = {}
        self.scan_errors: dict[str, list[str]] = defaultdict(list)
        self.read_errors: Counter[tuple[str, str]] = Counter()
        self.type_hint_errors: Counter[tuple[str, str]] = Counter()

        if target_keys:
            self._scan(target_keys)

    def _scan(self, target_keys: set[tuple[str, str]]) -> None:
        try:
            toc_files = sorted(
                self.cache_dir.glob("H.*.toc"),
                key=lambda path: path.name.casefold(),
            )
        except OSError as exc:
            raise RepairError(
                f"Could not enumerate base H TOCs in {self.cache_dir}: {exc}"
            ) from exc

        if not toc_files:
            raise RepairError(
                f"Base Cache.Windows contains no H.*.toc files: {self.cache_dir}"
            )

        target_namespaces = {namespace for namespace, _logical_path in target_keys}
        progress = ActivityProgress("Scanning base")
        scanned_entries = 0
        matched_entries = 0
        try:
            for toc_index, toc_path in enumerate(toc_files, 1):
                if not toc_path.name.startswith("H.") or not toc_path.name.casefold().endswith(".toc"):
                    continue
                package = toc_path.name[2:-4]
                if not package:
                    continue
                namespace = _cache_namespace_from_package(package)
                if namespace not in target_namespaces:
                    continue
                try:
                    for entry in iter_toc_entries(toc_path):
                        scanned_entries += 1
                        key = (namespace, entry.logical_path)
                        if key in target_keys:
                            self.entries.setdefault(key, []).append(entry)
                            matched_entries += 1
                        if scanned_entries == 1 or scanned_entries % 512 == 0:
                            progress.update(
                                scanned_entries,
                                extra=(
                                    f"{toc_index}/{len(toc_files)} TOCs | "
                                    f"{matched_entries} matches"
                                ),
                                detail=toc_path.name,
                            )
                except RepairError as exc:
                    self.scan_errors[namespace].append(str(exc))
        finally:
            progress.finish()

    def common_header_metadata(
        self,
        namespace: str,
        logical_path: str,
    ) -> tuple[list[tuple[str, int | None, CacheEntry]], bool]:
        result: list[tuple[str, int | None, CacheEntry]] = []
        had_read_error = False
        for entry in self.entries.get((namespace, logical_path), []):
            try:
                header = decompress_cache_entry(entry, self.oodle)
            except RepairError as exc:
                had_read_error = True
                reason = _single_line_console_text(exc)
                self.read_errors[(entry.cache_path.name, reason)] += 1
                continue

            if len(header) < 16:
                had_read_error = True
                reason = "CommonHeader is too short to contain the manifest hash."
                self.read_errors[(entry.cache_path.name, reason)] += 1
                continue

            header_hash = header[:16]
            type_id: int | None = None
            try:
                _parsed_hash, type_id = parse_common_header(header)
            except RepairError as exc:
                reason = _single_line_console_text(exc)
                self.type_hint_errors[(entry.cache_path.name, reason)] += 1

            result.append((b64m_encode(header_hash), type_id, entry))
        return result, had_read_error

    def namespace_has_scan_errors(self, namespace: str) -> bool:
        return bool(self.scan_errors.get(namespace))

    def print_read_error_summary(self, *, limit: int = 5) -> None:
        total = sum(self.read_errors.values())
        if not total:
            return
        verb = "was" if total == 1 else "were"
        print_warning(
            f"{total} base CommonHeader {_plural(total, 'read/decompression failure')} {verb} encountered.",
            prefix="[Base]",
        )
        for (cache_name, reason), count in self.read_errors.most_common(limit):
            print(f"[Base]   {count}x {cache_name} | {reason}")
        remaining = len(self.read_errors) - limit
        if remaining > 0:
            print(
                f"[Base]   ... {remaining} additional "
                f"{_plural(remaining, 'failure kind')}"
            )

    def print_type_hint_notice(self) -> None:
        total = sum(self.type_hint_errors.values())
        if total:
            print(
                f"[Base] CommonHeader type hints unavailable for {total} "
                f"{_plural(total, 'entry', 'entries')}; hash comparison remained usable."
            )

def repair_object(
    *,
    content_root: Path,
    name: str,
    expected_hash: str,
    oodle: Oodle,
    label: str,
) -> tuple[str, str | None, int | None]:
    try:
        destination = local_path(content_root, name)
    except RepairError as exc:
        return "failed", _single_line_console_text(exc), None
    existed = destination.is_file()

    if existed:
        try:
            existing = destination.read_bytes()
        except OSError as exc:
            print(f"[{label} check failed] {name} | {_single_line_console_text(exc)}")
        else:
            try:
                validate_shcc(
                    existing,
                    expected_hash,
                    oodle,
                    progress_name=name,
                )
            except RepairError as exc:
                print(
                    f"[{label} repairing] Existing asset is invalid: {name} | "
                    f"{_single_line_console_text(exc)}"
                )
            else:
                return "present", None, None

    url = cdn_url(name)
    body, error, http_status = download_asset(
        url,
        display_name=name,
        expected_hash=expected_hash,
        oodle=oodle,
    )

    if body is not None:
        try:
            atomic_write(destination, body, progress_label="Saving", display_name=name)
        except (OSError, RepairError) as exc:
            return "failed", f"could not save downloaded asset: {_single_line_console_text(exc)}", http_status
        return ("repaired" if existed else "downloaded"), "CDN", http_status

    return "failed", error or "downloaded object verification failed", http_status

def _unique_openwf_404_objects(lines: list[str]) -> list[str]:
    objects: list[str] = []
    seen: set[str] = set()

    for line in lines:
        match = OPENWF_404_RE.search(line)
        if match is None:
            continue
        path = match.group("path")
        if path not in seen:
            seen.add(path)
            objects.append(path)

    return objects

def extract_openwf_missing_objects(log_path: Path) -> tuple[list[str], int, bool]:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RepairError(f"Could not read OpenWF trace log {log_path}: {exc}") from exc

    lines = text.splitlines()
    all_objects = _unique_openwf_404_objects(lines)

    # Never fall back to the entire daily log. Without a session boundary we cannot
    # know whether an old 404 belongs to the patch currently being repaired.
    start_index: int | None = None
    for index in range(len(lines) - 1, -1, -1):
        if "Using log file:" in lines[index]:
            start_index = index
            break

    if start_index is None:
        return [], len(all_objects), False

    current_objects = _unique_openwf_404_objects(lines[start_index:])
    ignored = max(0, len(all_objects) - len(current_objects))
    return current_objects, ignored, True

@dataclass(frozen=True, slots=True)
class PackagesParentIndex:
    version: int
    entity_count: int
    parents: dict[str, str]
    layout: str
    directory_blocks: int = 0

def _packages_u32(data: bytes, offset: int, what: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise RepairError(f"Truncated Packages.bin while reading {what}.")
    return struct.unpack_from("<I", data, offset)[0]

def _packages_v46_dir_block_candidate(data: bytes, offset: int) -> bool:
    """Cheap structural check for the start of a v46 shared-directory block.

    The byte after the directory string is metadata, not a reliable constant.
    One verified sample happened to contain 0x01, while the real U44.0.1 file
    reaches later blocks containing 0x00.  The reference decoder merely skips
    this byte, so use the following entity count as the structural check instead.
    """
    if offset < 0 or offset + 9 > len(data):
        return False
    dir_len = struct.unpack_from("<I", data, offset)[0]
    if not 1 <= dir_len <= 4096:
        return False
    metadata_offset = offset + 4 + dir_len
    if metadata_offset + 5 > len(data):
        return False
    raw = data[offset + 4:metadata_offset]
    if not raw.startswith(b"/"):
        return False
    # Paths seen in Packages.bin are byte strings. ASCII is overwhelmingly the
    # common case, but v46 reference decoders use latin-1 semantics, so do not
    # reject a candidate solely because one byte is >= 0x80.
    if any(byte == 0 or byte < 0x20 for byte in raw):
        return False

    # metadata byte @ metadata_offset is intentionally not interpreted.
    type_count = struct.unpack_from("<I", data, metadata_offset + 1)[0]
    return 1 <= type_count <= 5_000_000

def _parse_packages_v46_entity_table(
    data: bytes,
    table_offset: int,
    entity_count: int,
    *,
    collect_parents: bool,
) -> tuple[dict[str, str], int, int]:
    """Parse/validate the v46 directory-block table.

    Returns (parents, directory_blocks, end_offset). When collect_parents is
    False, the same full structural validation is performed without retaining
    the ~hundreds-of-thousands-entry mapping. This lets the locator prove that a
    candidate is really the entity table instead of relying on comFlags/comSize
    heuristics that are irrelevant to parent resolution.
    """
    offset = table_offset
    parents: dict[str, str] = {}
    seen = 0
    directory_blocks = 0
    n = len(data)

    def require(size: int, what: str) -> None:
        if size < 0 or offset + size > n:
            raise RepairError(f"Truncated Packages.bin v46 while reading {what}.")

    def read_u32(what: str) -> int:
        nonlocal offset
        require(4, what)
        value = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        return value

    def read_text(what: str, *, max_len: int = 65536) -> str:
        nonlocal offset
        size = read_u32(f"{what} length")
        if size > max_len:
            raise RepairError(f"Unreasonable Packages.bin v46 {what} length: {size}.")
        require(size, what)
        raw = data[offset:offset + size]
        offset += size
        if b"\x00" in raw:
            raise RepairError(f"Embedded NUL in Packages.bin v46 {what}.")
        # Renovice's verified v46 decoder treats these fields as byte strings
        # and decodes latin-1. That is safer than rejecting the whole table when
        # a future path contains a high-bit byte.
        return raw.decode("latin1")

    while seen < entity_count:
        directory = read_text("directory name", max_len=4096)
        if not directory.startswith("/"):
            raise RepairError(f"Invalid Packages.bin v46 directory block: {directory!r}.")

        # One byte of per-directory metadata follows the shared directory name.
        # Do not require it to be 0x01: the U44.0.1 file contains 0x00 in later
        # blocks, and the reference decoder simply advances over this byte.
        require(1, "directory block metadata")
        offset += 1

        type_count = read_u32("directory entity count")
        remaining = entity_count - seen
        if not 1 <= type_count <= remaining:
            raise RepairError(
                f"Unreasonable Packages.bin v46 directory entity count {type_count}; "
                f"{remaining} entity/ies remain."
            )
        directory_blocks += 1

        for _ in range(type_count):
            filename = read_text("file name")
            require(3, "entity metadata")
            offset += 3
            base = read_text("parent type")

            if collect_parents:
                full_path = directory + filename
                if not base:
                    parent = ""
                elif base.startswith("/"):
                    parent = base
                else:
                    parent = directory + base
                parents[full_path] = parent
            seen += 1

    if seen != entity_count:
        raise RepairError(
            f"Packages.bin v46 entity count mismatch: parsed {seen}, expected {entity_count}."
        )

    return parents, directory_blocks, offset

def _locate_packages_v46(data: bytes) -> tuple[int, int, int]:
    """Return (version, entity_count, entity_table_offset) for Packages.bin v46.

    Parent-chain decoding does not need the compressed metadata text buffers
    (comFlags/comSize/comZ frames). The previous locator nevertheless required
    guessed comFlags/comSize layouts to validate the file, which made real U44
    Packages.bin files fail even when their entity table was otherwise usable.

    The useful invariant is simpler and stronger:
      * comZ starts with an embedded full Zstandard dictionary (37 A4 30 EC),
      * the u32 immediately before it is comZ length,
      * entityCount follows exactly at the end of comZ,
      * shortly after entityCount begins a directory-block table that parses
        exactly entityCount entities.

    We therefore anchor on comZ and accept a candidate only after fully parsing
    the complete entity table. No hard-coded build offsets are required.
    """
    if len(data) < 8192:
        raise RepairError("Packages.bin is too small for the v46 layout.")
    if _packages_u32(data, 16, "header size") != 20:
        raise RepairError("Unsupported Packages.bin header size; expected 20.")
    version = _packages_u32(data, 20, "version")
    if version != 46:
        raise UnsupportedPackagesVersionError(
            f"Unsupported Packages.bin version {version}; the current repairer "
            "supports only the verified v46 directory-block layout."
        )
    if _packages_u32(data, 24, "flags") != 1:
        raise RepairError("Unsupported Packages.bin flags value.")

    magic = b"\x37\xA4\x30\xEC"
    search_from = 2048
    candidates = 0
    table_errors: list[str] = []

    while True:
        dictionary_offset = data.find(magic, search_from)
        if dictionary_offset < 0:
            break
        search_from = dictionary_offset + 1
        if dictionary_offset < 4:
            continue

        com_z_len_offset = dictionary_offset - 4
        com_z_len = struct.unpack_from("<I", data, com_z_len_offset)[0]
        entity_count_offset = dictionary_offset + com_z_len
        if com_z_len < 4096 or entity_count_offset + 4 > len(data):
            continue

        entity_count = struct.unpack_from("<I", data, entity_count_offset)[0]
        if not 1 <= entity_count <= 10_000_000:
            continue
        candidates += 1

        # Renovice's verified v46 sample has a 15-byte metadata gap here. Scan a
        # wider but still tiny region so this survives nearby-build variations.
        scan_start = entity_count_offset + 4
        scan_end = min(len(data) - 9, scan_start + 8192)
        for table_offset in range(scan_start, scan_end + 1):
            if not _packages_v46_dir_block_candidate(data, table_offset):
                continue
            try:
                _parents, _directory_blocks, end_offset = _parse_packages_v46_entity_table(
                    data,
                    table_offset,
                    entity_count,
                    collect_parents=False,
                )
                trailing = len(data) - end_offset
                if trailing < 0 or trailing > 4096:
                    raise RepairError(
                        f"directory-block table left {trailing} unexplained {_plural(trailing, 'byte')} "
                        "after the entity table"
                    )
            except RepairError as exc:
                if len(table_errors) < 3:
                    table_errors.append(
                        f"table candidate 0x{table_offset:X}: {exc}"
                    )
                continue
            return version, entity_count, table_offset

    detail = ""
    if candidates == 0:
        detail = " No plausible comZ dictionary/length candidate was found."
    elif table_errors:
        detail = " " + " | ".join(table_errors)
    raise RepairError(
        "Could not structurally locate/validate the Packages.bin v46 entity table."
        + detail
    )

def _read_packages_parent_index_v46(data: bytes) -> PackagesParentIndex:
    version, entity_count, table_offset = _locate_packages_v46(data)
    parents, directory_blocks, _end_offset = _parse_packages_v46_entity_table(
        data,
        table_offset,
        entity_count,
        collect_parents=True,
    )

    return PackagesParentIndex(
        version=version,
        entity_count=entity_count,
        parents=parents,
        layout=f"v{version} directory-block",
        directory_blocks=directory_blocks,
    )

def _read_packages_parent_index(header: bytes) -> PackagesParentIndex:
    """Parse the currently verified Packages.bin directory-block layout.

    The standalone repairer intentionally keeps only parser layouts that have
    been validated against a real repair workflow. Retired/experimental parser
    variants remain available through Git history instead of accumulating here.
    """
    if len(header) < 28:
        raise RepairError("Packages.bin is truncated before its fixed header.")
    version = struct.unpack_from("<I", header, 20)[0]
    if version != 46:
        raise UnsupportedPackagesVersionError(
            f"Unsupported Packages.bin version {version}; the current repairer "
            "supports only the verified v46 directory-block layout."
        )
    return _read_packages_parent_index_v46(header)

def _find_packages_objects(content_root: Path) -> list[tuple[Path, re.Match[str]]]:
    directory = content_root / "0"
    if not directory.is_dir():
        return []

    found: list[tuple[Path, re.Match[str]]] = []
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise RepairError(f"Could not enumerate captured Packages.bin objects in {directory}: {exc}") from exc

    for path in entries:
        if not path.is_file():
            continue
        match = PACKAGES_OBJECT_RE.fullmatch(path.name)
        if match is not None:
            found.append((path, match))

    found.sort(key=lambda item: item[0].name.casefold())
    return found

def _load_packages_parent_index(
    content_root: Path,
    oodle: Oodle,
) -> tuple[Path, int, PackagesParentIndex]:
    candidates = _find_packages_objects(content_root)
    if not candidates:
        raise RepairError(
            "No captured OpenWF Content/0/Packages.bin!TYPE_HASH object was found."
        )

    errors: list[str] = []
    integrity_valid: list[tuple[Path, int, bytes]] = []
    progress = TransientLine(show_after=0.0)
    try:
        for path, match in candidates:
            width = max(20, shutil.get_terminal_size((120, 24)).columns)
            plain_prefix = "[Analyzing Packages] working | "
            available = max(4, width - len(plain_prefix) - 1)
            if len(path.name) <= available:
                shown_name = path.name
            elif available <= 3:
                shown_name = path.name[-available:]
            else:
                shown_name = "..." + path.name[-(available - 3):]
            plain = plain_prefix + shown_name
            styled = (
                "[Analyzing Packages] "
                + _color("working", ANSI_CYAN, sys.stdout)
                + " | "
                + shown_name
            )
            progress.render(styled, plain, force=True)
            try:
                data = path.read_bytes()
                header, digest = shcc_header_and_hash(data, oodle)
                expected_hash = match.group("hash")
                actual_hash = b64m_encode(digest)
                if actual_hash != expected_hash:
                    errors.append(
                        f"{path.name}: SHCC hash mismatch (expected {expected_hash}, got {actual_hash})"
                    )
                    continue
                integrity_valid.append((path, int(match.group("type"), 16), header))
            except (OSError, RepairError, ValueError) as exc:
                errors.append(f"{path.name}: {exc}")
    finally:
        progress.finish()

    # Ambiguity is decided from object integrity, before interpreting the
    # Packages payload. Otherwise a stale v46 object could silently win merely
    # because the current build's v47+ object is intentionally unsupported.
    if len(integrity_valid) > 1:
        names = "; ".join(path.name for path, _type_id, _header in integrity_valid[:3])
        if len(integrity_valid) > 3:
            names += f"; ... {len(integrity_valid) - 3} more"
        raise PackagesAmbiguityError(
            "Multiple integrity-valid captured Packages.bin objects were found; "
            "remove stale objects so the target build is unambiguous: " + names
        )

    if not integrity_valid:
        detail = "; ".join(errors[:3])
        if len(errors) > 3:
            detail += f"; ... {len(errors) - 3} more"
        raise RepairError(f"Could not validate any captured Packages.bin object: {detail}")

    path, type_id, header = integrity_valid[0]
    try:
        index = _read_packages_parent_index(header)
    except UnsupportedPackagesVersionError:
        raise
    except RepairError as exc:
        raise UnsupportedPackagesLayoutError(
            f"Integrity-valid {path.name} uses Packages.bin data that does not match "
            f"the validated v46 layout: {exc}"
        ) from exc
    return path, type_id, index

def _packages_parent_chain(
    logical_path: str,
    parents: dict[str, str],
    *,
    max_depth: int = 128,
) -> list[str]:
    chain: list[str] = []
    seen = {logical_path}
    current = logical_path

    for _ in range(max_depth):
        parent = parents.get(current, "")
        if not parent or parent in seen:
            break
        chain.append(parent)
        seen.add(parent)
        current = parent

    return chain

def collect_manifest_assets(
    manifests: list[tuple[Path, re.Match[str]]],
    oodle: Oodle,
) -> tuple[list[ManifestAsset], int]:
    assets: list[ManifestAsset] = []
    failures = 0

    for manifest_path, match in manifests:
        suffix = match.group("suffix") or ""
        kind = match.group("kind")
        if kind == "Windows":
            namespace = "0" + suffix
        elif kind == "Dx11":
            namespace = "9"
        else:
            namespace = "A"
        expected_manifest_hash = match.group("hash")

        print(f"[Manifest] {manifest_path.name}")

        try:
            data = manifest_path.read_bytes()
            header, digest = shcc_header_and_hash(
                data,
                oodle,
                progress_name=manifest_path.name,
            )
        except (OSError, RepairError) as exc:
            print_error(f"Could not read/parse manifest: {exc}")
            failures += 1
            continue

        actual_manifest_hash = b64m_encode(digest)
        if actual_manifest_hash != expected_manifest_hash:
            print_error(
                "Manifest SHCC hash does not match its filename: "
                f"expected {expected_manifest_hash}, got {actual_manifest_hash}"
            )
            failures += 1
            continue

        section_counts: Counter[str] = Counter()
        parsed_assets: list[ManifestAsset] = []
        progress = ActivityProgress("Parsing manifest")
        try:
            manifest_version = _manifest_header_version(header)
            for section, asset_path, manifest_hash in parse_manifest_header(header):
                section_counts[section] += 1
                parsed_assets.append(
                    ManifestAsset(
                        namespace=namespace,
                        section=section,
                        logical_path=asset_path,
                        manifest_hash=manifest_hash,
                    )
                )
                count = len(parsed_assets)
                if count == 1 or count % 512 == 0:
                    progress.update(
                        count,
                        extra=section,
                        detail=manifest_path.name,
                    )
        except UnsupportedManifestVersionError:
            # A new manifest version is a compatibility boundary, not a damaged
            # individual manifest that can be counted and ignored.
            progress.finish()
            raise
        except RepairError as exc:
            # Clear the transient row before emitting a permanent error line.
            progress.finish()
            print_error(f"Could not parse cache manifest: {exc}")
            failures += 1
            continue
        finally:
            progress.finish()

        print(
            f"[Manifest] v{manifest_version} | Sections: "
            + " | ".join(
                f"{section}: {section_counts.get(section, 0)}"
                for section in MANIFEST_SECTION_NAMES
            )
        )
        assets.extend(parsed_assets)

    return assets, failures

def _dedupe_manifest_assets(assets: list[ManifestAsset]) -> tuple[list[ManifestAsset], int]:
    unique: list[ManifestAsset] = []
    seen: set[tuple[str, str, bytes]] = set()
    duplicates = 0
    progress = ActivityProgress("Indexing manifest", len(assets))
    try:
        for index, asset in enumerate(assets, 1):
            key = (asset.namespace, asset.logical_path, asset.manifest_hash)
            if key in seen:
                duplicates += 1
            else:
                seen.add(key)
                unique.append(asset)
            if index == 1 or index % 1024 == 0 or index == len(assets):
                progress.update(
                    index,
                    extra=f"{len(unique)} unique | {duplicates} duplicates",
                )
    finally:
        progress.finish()
    return unique, duplicates

def _existing_exact_object(
    resolver: TypeResolver,
    asset: ManifestAsset,
) -> ObservedObject | None:
    evidence = resolver.patch_evidence
    if evidence is None:
        return None
    return evidence.exact_objects.get(
        (asset.namespace, asset.logical_path, asset.hash_b64)
    )

def resolve_manifest_asset_type(
    asset: ManifestAsset,
    *,
    resolver: TypeResolver,
) -> tuple[int | None, str | None]:
    type_id, source = resolver.resolve_patch(asset.namespace, asset.logical_path)
    if type_id is not None:
        return type_id, source

    type_id, source = resolver.resolve_current(asset.logical_path, asset.namespace)
    if type_id is not None:
        return type_id, source

    return None, None

def classify_manifest_against_base(
    assets: list[ManifestAsset],
    base_cache: BaseHeaderCache,
) -> tuple[list[ManifestAsset], int, int, dict[tuple[str, str], int]]:
    changed: list[ManifestAsset] = []
    unchanged = 0
    unknown = 0
    base_type_hints: dict[tuple[str, str], int] = {}
    cached: dict[tuple[str, str, str], tuple[str, int | None]] = {}

    progress = ActivityProgress("Comparing base", len(assets))
    try:
        for index, asset in enumerate(assets, 1):
            key = (asset.namespace, asset.logical_path, asset.hash_b64)
            classification = cached.get(key)
            if classification is None:
                metadata, had_read_error = base_cache.common_header_metadata(
                    asset.namespace, asset.logical_path
                )
                exact = [item for item in metadata if item[0] == asset.hash_b64]
                if exact:
                    exact_types = {
                        type_id
                        for _hash, type_id, _entry in exact
                        if type_id is not None
                    }
                    hint = next(iter(exact_types)) if len(exact_types) == 1 else None
                    classification = ("unchanged", hint)
                elif had_read_error:
                    classification = ("unknown", None)
                elif metadata:
                    types = {
                        type_id
                        for _hash, type_id, _entry in metadata
                        if type_id is not None
                    }
                    hint = next(iter(types)) if len(types) == 1 else None
                    classification = ("changed", hint)
                elif base_cache.namespace_has_scan_errors(asset.namespace):
                    classification = ("unknown", None)
                else:
                    classification = ("new", None)
                cached[key] = classification

            state, hint = classification
            if hint is not None:
                base_type_hints.setdefault((asset.namespace, asset.logical_path), hint)

            if state == "unchanged":
                unchanged += 1
            elif state == "unknown":
                unknown += 1
            else:
                changed.append(asset)

            if index == 1 or index % 256 == 0 or index == len(assets):
                progress.update(
                    index,
                    extra=(
                        f"Unchanged {unchanged} | Changed/new {len(changed)} | "
                        f"Unknown {unknown}"
                    ),
                )
    finally:
        progress.finish()

    return changed, unchanged, unknown, base_type_hints

def repair_manifest_asset(
    asset: ManifestAsset,
    *,
    content_root: Path,
    source_content_root: Path,
    oodle: Oodle,
    resolver: TypeResolver,
    label: str,
    base_type_hint: int | None = None,
    openwf_type_hint: int | None = None,
) -> tuple[str, str | None, str | None, int | None]:
    exact_object = _existing_exact_object(resolver, asset)
    if exact_object is not None:
        try:
            existing = exact_object.path.read_bytes()
        except OSError as exc:
            print(f"[{label} check failed] {exact_object.path} | {_single_line_console_text(exc)}")
        else:
            if verify_shcc(
                existing,
                asset.hash_b64,
                oodle,
                progress_name=exact_object.path.name,
            ):
                try:
                    existing_name = exact_object.path.relative_to(source_content_root).as_posix()
                except ValueError:
                    existing_name = exact_object.path.name
                try:
                    destination = local_path(content_root, existing_name)
                except RepairError as exc:
                    return "failed", _single_line_console_text(exc), existing_name, None
                if destination != exact_object.path:
                    try:
                        atomic_write(
                            destination,
                            existing,
                            progress_label="Copying",
                            display_name=existing_name,
                        )
                    except (OSError, RepairError) as exc:
                        return "failed", f"could not copy existing patch object: {_single_line_console_text(exc)}", existing_name, None
                    return (
                        "copied",
                        f"existing patch object 0x{exact_object.type_id:X}",
                        existing_name,
                        None,
                    )
                return (
                    "present",
                    f"existing patch object 0x{exact_object.type_id:X}",
                    existing_name,
                    None,
                )

    type_id, source = resolve_manifest_asset_type(
        asset,
        resolver=resolver,
    )
    if type_id is None and base_type_hint is not None:
        type_id = base_type_hint
        source = "original base same-path CommonHeader type hint"
    if type_id is None and openwf_type_hint is not None:
        type_id = openwf_type_hint
        source = "exact current-session OpenWF 404 fallback"

    if type_id is None:
        return "skipped", "type unresolved", None, None

    name = cache_name(
        asset.logical_path,
        type_id,
        asset.hash_b64,
        asset.namespace,
    )
    status, detail, http_status = repair_object(
        content_root=content_root,
        name=name,
        expected_hash=asset.hash_b64,
        oodle=oodle,
        label=label,
    )
    if detail is None:
        return status, source, name, http_status
    if source:
        return status, f"{detail}; type from {source}", name, http_status
    return status, detail, name, http_status

def prepare_openwf_404s(
    requested_log: Path,
) -> tuple[Path, list[str], int, bool]:
    log_path = requested_log.expanduser()
    if not log_path.is_file():
        raise RepairError(f"OpenWF trace log is not a file: {log_path}")
    log_path = log_path.resolve()
    objects, ignored, session_found = extract_openwf_missing_objects(log_path)
    return log_path, objects, ignored, session_found

def _print_installed_cache_summary(
    label: str,
    cache: BaseHeaderCache,
    requested_paths: int,
) -> None:
    matched_entries = sum(len(entries) for entries in cache.entries.values())
    print(f"{label}: {cache.cache_dir}")
    print(
        f"{label} targeted matches: {matched_entries} "
        f"across {requested_paths} requested logical {_plural(requested_paths, 'path')}"
    )
    scan_error_count = sum(len(errors) for errors in cache.scan_errors.values())
    if scan_error_count:
        print_warning(
            f"{scan_error_count} {label} TOC {_plural(scan_error_count, 'file')} could not be parsed."
        )

def _select_manifest_sections(
    assets: list[ManifestAsset],
    section_mode: str,
) -> list[ManifestAsset]:
    if section_mode == "all":
        return list(assets)
    if section_mode == "no-stripped":
        return [asset for asset in assets if asset.section != "stripped"]
    if section_mode == "only-stripped":
        return [asset for asset in assets if asset.section == "stripped"]
    raise RepairError(f"Unknown manifest section mode: {section_mode}")

def _manifest_object_keys(assets: list[ManifestAsset]) -> set[tuple[str, str, str]]:
    return {(asset.namespace, asset.logical_path, asset.hash_b64) for asset in assets}

def _filter_openwf_by_section(
    objects: list[str],
    all_assets: list[ManifestAsset],
    selected_assets: list[ManifestAsset],
    section_mode: str,
) -> tuple[list[str], int]:
    if section_mode == "all":
        return objects, 0
    all_keys = _manifest_object_keys(all_assets)
    selected_keys = _manifest_object_keys(selected_assets)
    kept: list[str] = []
    omitted = 0
    for request_path in objects:
        match = CDN_OBJECT_RE.fullmatch(request_path)
        if match is None:
            continue
        key = (match.group("namespace"), match.group("logical"), match.group("hash"))
        if section_mode == "only-stripped":
            include = key in selected_keys
        else:
            include = key not in all_keys or key in selected_keys
        if include:
            kept.append(request_path)
        else:
            omitted += 1
    return kept, omitted

def _openwf_type_hints(objects: list[str]) -> dict[tuple[str, str, str], int]:
    hints: dict[tuple[str, str, str], int] = {}
    ambiguous: set[tuple[str, str, str]] = set()
    for request_path in objects:
        match = CDN_OBJECT_RE.fullmatch(request_path)
        if match is None:
            continue
        key = (match.group("namespace"), match.group("logical"), match.group("hash"))
        if key in ambiguous:
            continue
        try:
            type_id = int(match.group("type"), 16)
        except ValueError:
            continue
        previous = hints.get(key)
        if previous is None:
            hints[key] = type_id
        elif previous != type_id:
            hints.pop(key, None)
            ambiguous.add(key)
    return hints

def _strip_manifest_404s(
    objects: list[str],
    manifest_keys: set[tuple[str, str, str]],
) -> list[str]:
    remaining: list[str] = []
    for request_path in objects:
        match = CDN_OBJECT_RE.fullmatch(request_path)
        if match is None:
            continue
        key = (match.group("namespace"), match.group("logical"), match.group("hash"))
        if key not in manifest_keys:
            remaining.append(request_path)
    return remaining

def _create_stripped_output_root(requested: Path | None = None) -> Path:
    if requested is not None:
        candidate = requested.expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        candidate = _validate_windows_output_path(
            candidate.resolve(),
            label="Stripped-assets output path",
        )
        while True:
            try:
                candidate.mkdir(parents=True, exist_ok=False)
                try:
                    usage = shutil.disk_usage(candidate)
                    _warn_low_disk_space(candidate, int(usage.free))
                except OSError:
                    pass
                return candidate
            except FileExistsError as exc:
                raise RepairError(
                    f"Stripped-assets output path already exists: {candidate}"
                ) from exc
            except OSError as exc:
                if not _is_disk_full_error(exc):
                    raise RepairError(
                        f"Could not create stripped-assets output folder {candidate}: {exc}"
                    ) from exc
                _wait_for_disk_space(candidate.parent, 0, str(candidate))

    base = time.strftime("%Y-%m-%d_%H-%M-%S")
    cwd = Path.cwd()
    for suffix in range(0, 1000):
        middle = "" if suffix == 0 else f"_{suffix + 1}"
        candidate = _validate_windows_output_path(
            cwd / f"{base}{middle}_stripped-assets",
            label="Stripped-assets output path",
        )
        while True:
            try:
                candidate.mkdir(parents=False, exist_ok=False)
                resolved = candidate.resolve()
                try:
                    usage = shutil.disk_usage(resolved)
                    _warn_low_disk_space(resolved, int(usage.free))
                except OSError:
                    pass
                return resolved
            except FileExistsError:
                break
            except OSError as exc:
                if not _is_disk_full_error(exc):
                    raise RepairError(f"Could not create stripped-assets output folder {candidate}: {exc}") from exc
                _wait_for_disk_space(candidate.parent, 0, str(candidate))
    raise RepairError("Could not choose a unique stripped-assets output folder name.")

def run(
    target_root: Path,
    base_root: Path | None = None,
    *,
    patch_types_only: bool = False,
    openwf_log: Path | None = None,
    section_mode: str = "all",
    stripped_output: Path | None = None,
) -> int:
    if stripped_output is not None and section_mode != "only-stripped":
        raise RepairError("Custom stripped output requires only-stripped mode.")
    if not target_root.exists():
        raise RepairError(f"Target path does not exist: {target_root}")
    if not target_root.is_dir():
        raise RepairError(f"Target path is not a directory: {target_root}")

    target_root = target_root.resolve()
    if section_mode != "only-stripped":
        try:
            usage = shutil.disk_usage(target_root)
            _warn_low_disk_space(target_root, int(usage.free))
        except OSError:
            pass
    content_root = resolve_content_root(target_root)
    manifests = manifest_files(content_root)
    oodle = Oodle()

    print(f"Warframe/update-patch root: {target_root}")
    print(f"OpenWF Content: {content_root}")
    print(f"Manifests: {len(manifests)}")
    print()

    manifest_assets_raw, manifest_failures = collect_manifest_assets(manifests, oodle)
    all_manifest_assets, all_duplicate_entries = _dedupe_manifest_assets(manifest_assets_raw)
    if section_mode == "all":
        manifest_assets = all_manifest_assets
    else:
        selected_manifest_raw = _select_manifest_sections(manifest_assets_raw, section_mode)
        manifest_assets, _ = _dedupe_manifest_assets(selected_manifest_raw)

    print()
    print(
        f"Manifest assets: {len(all_manifest_assets)} unique target "
        f"{_plural(len(all_manifest_assets), 'object')} "
        f"| duplicate entries ignored: {all_duplicate_entries}"
    )
    if section_mode == "no-stripped":
        print(f"[Sections] --no-stripped: {len(manifest_assets)} selected unique {_plural(len(manifest_assets), 'object')}.")
    elif section_mode == "only-stripped":
        print(f"[Sections] --only-stripped: {len(manifest_assets)} selected unique {_plural(len(manifest_assets), 'object')}.")
        if stripped_output is None:
            print("[Sections] Stripped update assets will be exported to a separate timestamped folder.")
        else:
            print("[Sections] Stripped update assets will be exported to the requested output folder.")
    manifest_section_totals = Counter(asset.section for asset in manifest_assets)
    print(
        "Manifest assets by section (unique after dedupe): "
        + " | ".join(
            f"{section}: {manifest_section_totals.get(section, 0)}"
            for section in MANIFEST_SECTION_NAMES
        )
    )

    observations = scan_existing_content_objects(content_root)
    print(f"Existing patch CDN objects: {len(observations)}")

    packages_index: PackagesParentIndex | None = None
    try:
        packages_path, packages_type, packages_index = _load_packages_parent_index(content_root, oodle)
        print(
            f"[Packages] Parent index: {packages_path.name} | "
            f"type 0x{packages_type:X} | {packages_index.layout} | "
            f"{len(packages_index.parents)} parent links"
        )
    except (
        PackagesAmbiguityError,
        UnsupportedPackagesVersionError,
        UnsupportedPackagesLayoutError,
    ):
        raise
    except RepairError as exc:
        print(f"[Packages] Parent metadata unavailable: {_single_line_console_text(exc)}")

    type_resolver = build_type_resolver(
        target_root,
        packages_index,
        observations,
        patch_types_only=patch_types_only,
    )

    if openwf_log is None:
        log_path, openwf_objects, ignored_historical, openwf_session_found = (
            None, [], 0, False
        )
    else:
        log_path, openwf_objects, ignored_historical, openwf_session_found = prepare_openwf_404s(
            openwf_log
        )

    full_completion = base_root is not None
    base_type_hints: dict[tuple[str, str], int] = {}
    unchanged_base = 0
    unknown_base = 0

    if full_completion:
        assert base_root is not None
        if not base_root.exists() or not base_root.is_dir():
            raise RepairError(f"Base path is not a directory: {base_root}")
        base_root = base_root.resolve()
        base_cache_dir = find_cache_windows_dir(base_root)
        if base_cache_dir is None:
            raise RepairError(
                "The base path must point to the original, unupdated Steam base with a "
                "Cache.Windows directory."
            )

        print()
        print("[Mode] Full update-patch completion.")
        print(f"[Base] Original unupdated Steam base: {base_root}")
        print(
            "[Base] Comparing target manifest hashes against the base H cache. "
            "Changed/new assets are patch candidates; manifest FontCache assets are "
            "also included proactively because the client may request them even when "
            "their base hash is unchanged."
        )

        all_manifest_keys = {(asset.namespace, asset.logical_path) for asset in manifest_assets}
        base_cache = BaseHeaderCache(
            base_cache_dir,
            all_manifest_keys,
            oodle,
        )
        _print_installed_cache_summary(
            "Base Cache.Windows",
            base_cache,
            len(all_manifest_keys),
        )

        (
            repair_assets,
            unchanged_base,
            unknown_base,
            base_type_hints,
        ) = classify_manifest_against_base(manifest_assets, base_cache)

        changed_new_candidates = len(repair_assets)
        repair_keys = _manifest_object_keys(repair_assets)
        fontcache_assets = [
            asset
            for asset in manifest_assets
            if "/Temp/FontCache/" in asset.logical_path
        ]
        fontcache_already_selected = sum(
            1
            for asset in fontcache_assets
            if (asset.namespace, asset.logical_path, asset.hash_b64) in repair_keys
        )
        proactive_fontcache = [
            asset
            for asset in fontcache_assets
            if (asset.namespace, asset.logical_path, asset.hash_b64) not in repair_keys
        ]
        repair_assets.extend(proactive_fontcache)

        print(
            "[Base] Comparison result: "
            f"changed/new: {changed_new_candidates} | "
            f"unchanged: {unchanged_base} | "
            f"unknown: {unknown_base}"
        )
        print(
            "[FontCache] Proactive manifest coverage: "
            f"{len(fontcache_assets)} target assets | "
            f"already changed/new: {fontcache_already_selected} | "
            f"additionally included: {len(proactive_fontcache)}"
        )
        base_cache.print_type_hint_notice()
        if unknown_base:
            base_cache.print_read_error_summary()
            print_warning(
                "Some target assets could not be classified from the original base. "
                "They will not be guessed/downloaded."
            )
    else:
        changed_new_candidates = 0
        proactive_fontcache = []
        print()
        print("[Mode] Patch-types-only diagnostic repair.")
        print(
            "[Mode] Base comparison is intentionally disabled in this diagnostic mode. "
            "FontCache candidates are taken directly from the target manifests and type "
            "resolution may use patch-local evidence plus the matching Warframe.x64.exe."
        )
        repair_assets = [
            asset
            for asset in manifest_assets
            if "/Temp/FontCache/" in asset.logical_path
        ]

    openwf_selection_assets = repair_assets if section_mode == "only-stripped" else manifest_assets
    openwf_objects, section_filtered_404s = _filter_openwf_by_section(
        openwf_objects, all_manifest_assets, openwf_selection_assets, section_mode
    )
    openwf_hints = _openwf_type_hints(openwf_objects)
    repair_asset_keys = _manifest_object_keys(repair_assets)
    manifest_404_hint_count = 0

    stripped_output_root: Path | None = None
    repair_content_root = content_root
    if section_mode == "only-stripped":
        stripped_output_root = _create_stripped_output_root(stripped_output)
        repair_content_root = stripped_output_root / "OpenWF" / "Content"
        print(f"[Sections] Stripped output: {stripped_output_root}")
        print("[Sections] Source patch OpenWF/Content is not modified; output uses the same OpenWF/Content layout.")

    print()
    if full_completion:
        print(f"Manifest completion candidates: {len(repair_assets)}")
    else:
        print(f"FontCache manifest candidates: {len(repair_assets)}")

    manifest_parse_failures = manifest_failures
    manifest_present = 0
    manifest_copied = 0
    manifest_downloaded = 0
    manifest_repaired = 0
    manifest_failed = 0
    manifest_skipped = 0
    manifest_section_results: dict[str, Counter[str]] = {
        section: Counter() for section in MANIFEST_SECTION_NAMES
    }
    repair_started = time.monotonic()
    for index, asset in enumerate(repair_assets, 1):
        if full_completion and (index == 1 or index % 500 == 0):
            total_candidates = len(repair_assets)
            percent = (index * 100.0 / total_candidates) if total_candidates else 100.0
            elapsed = max(0.0, time.monotonic() - repair_started)
            rate = (index - 1) / elapsed if elapsed > 0 and index > 1 else 0.0
            progress_label = "Stripped" if section_mode == "only-stripped" else "Completion"
            speed = f" | {rate:.0f}/s" if rate > 0 else ""
            print(
                f"[{progress_label}] Processing {index}/{total_candidates} "
                f"({percent:.1f}%){speed}..."
            )

        asset_key = (asset.namespace, asset.logical_path, asset.hash_b64)
        status, detail, resolved_name, http_status = repair_manifest_asset(
            asset,
            content_root=repair_content_root,
            source_content_root=content_root,
            oodle=oodle,
            resolver=type_resolver,
            label="Stripped" if section_mode == "only-stripped" else "Completion" if full_completion else "FontCache",
            base_type_hint=base_type_hints.get((asset.namespace, asset.logical_path)),
            openwf_type_hint=openwf_hints.get(asset_key),
        )
        if detail and "exact current-session OpenWF 404 fallback" in detail:
            manifest_404_hint_count += 1

        display_name = resolved_name or (
            f"{asset.namespace}{asset.logical_path}!<unresolved-type>_{asset.hash_b64}"
        )

        if status == "present":
            manifest_present += 1
            manifest_section_results[asset.section]["present"] += 1
        elif status == "copied":
            manifest_copied += 1
            manifest_section_results[asset.section]["copied"] += 1
            print(f"[Copied] {display_name} | {_single_line_console_text(detail)}", flush=True)
        elif status == "downloaded":
            manifest_downloaded += 1
            manifest_section_results[asset.section]["downloaded"] += 1
            print(f"{http_status_label(200)} {display_name} | {_single_line_console_text(detail)}", flush=True)
        elif status == "repaired":
            manifest_repaired += 1
            manifest_section_results[asset.section]["repaired"] += 1
            print(f"{http_status_label(http_status or 200)} [Repaired] {display_name} | {_single_line_console_text(detail)}", flush=True)
        elif status == "skipped":
            manifest_skipped += 1
            manifest_section_results[asset.section]["skipped"] += 1
            print(
                f"[Skipped] {asset.namespace}{asset.logical_path} "
                f"| hash {asset.hash_b64} | {_single_line_console_text(detail)}"
            )
        else:
            manifest_failed += 1
            manifest_section_results[asset.section]["failed"] += 1
            http = f" {http_status_label(http_status)}" if http_status is not None and http_status != 200 else ""
            reason = "" if http_status is not None and detail == f"HTTP {http_status}" else f" | {_single_line_console_text(detail)}"
            print(
                f"[Failed]{http} {asset.namespace}{asset.logical_path} "
                f"| hash {asset.hash_b64}{reason}"
            )

    openwf_objects = _strip_manifest_404s(
        openwf_objects, repair_asset_keys
    )

    if log_path is not None:
        print()
        print(f"[OpenWF] Trace log: {log_path}")
        if not openwf_session_found:
            print_warning(
                "No current-session 'Using log file:' marker was found; exact 404 recovery "
                "is skipped instead of using historical entries.",
                prefix="[OpenWF]",
            )
        print(f"[OpenWF] Current-session exact 404 type hints used for manifest candidates: {manifest_404_hint_count}")
        print(f"[OpenWF] Remaining unique hashed asset 404s for direct recovery: {len(openwf_objects)}")
        if ignored_historical:
            print(
                f"[OpenWF] Ignoring {ignored_historical} unique 404s from older "
                "server sessions in the same daily log."
            )
        if section_filtered_404s:
            print(
                f"[OpenWF] Ignoring {section_filtered_404s} current-session "
                f"{_plural(section_filtered_404s, '404')} "
                "outside the selected manifest-section mode."
            )

    openwf_present = 0
    openwf_downloaded = 0
    openwf_repaired = 0
    openwf_failed = 0

    for request_path in openwf_objects:
        match = CDN_OBJECT_RE.fullmatch(request_path)
        if match is None:
            continue

        expected_hash = match.group("hash")
        name = request_path.lstrip("/")

        status, detail, http_status = repair_object(
            content_root=repair_content_root,
            name=name,
            expected_hash=expected_hash,
            oodle=oodle,
            label="OpenWF",
        )

        if status == "present":
            openwf_present += 1
        elif status == "downloaded":
            openwf_downloaded += 1
            print(f"[OpenWF {_color('200', ANSI_GREEN, sys.stdout)}] {name}", flush=True)
        elif status == "repaired":
            openwf_repaired += 1
            print(f"[OpenWF {_color(str(http_status or 200), ANSI_GREEN, sys.stdout)}] [Repaired] {name} | {_single_line_console_text(detail)}", flush=True)
        else:
            openwf_failed += 1
            http = f" {http_status_label(http_status)}" if http_status is not None and http_status != 200 else ""
            reason = "" if http_status is not None and detail == f"HTTP {http_status}" else f" | {_single_line_console_text(detail)}"
            print(f"[OpenWF failed]{http} {name}{reason}")

    print()
    if oodle.path is not None:
        print(f"Oodle: {oodle.path}")

    summary_label = (
        "Stripped export"
        if section_mode == "only-stripped"
        else "Full manifest completion" if full_completion
        else "FontCache repair"
    )
    copied_summary = f"Copied: {manifest_copied} | " if section_mode == "only-stripped" else ""
    print(
        f"{summary_label}: "
        f"Present: {manifest_present} | "
        f"{copied_summary}"
        f"Downloaded: {manifest_downloaded} | "
        f"Repaired: {manifest_repaired} | "
        f"Failed: {manifest_failed} | "
        f"Skipped: {manifest_skipped}"
    )
    section_summary_label = (
        "Manifest completion by section (unique repair candidates):"
        if full_completion
        else "FontCache repair by manifest section (unique candidates):"
    )
    print(section_summary_label)
    for section in MANIFEST_SECTION_NAMES:
        counts = manifest_section_results[section]
        candidates = sum(counts.values())
        copied_section = (
            f"Copied: {counts.get('copied', 0)} | "
            if section_mode == "only-stripped"
            else ""
        )
        print(
            f"  {section}: Candidates: {candidates} | "
            f"Present: {counts.get('present', 0)} | "
            f"{copied_section}"
            f"Downloaded: {counts.get('downloaded', 0)} | "
            f"Repaired: {counts.get('repaired', 0)} | "
            f"Failed: {counts.get('failed', 0)} | "
            f"Skipped: {counts.get('skipped', 0)}"
        )

    print(f"Manifest parse failures: {manifest_parse_failures}")
    if full_completion:
        print(
            "Base comparison: "
            f"Unchanged: {unchanged_base} | "
            f"Changed/new candidates: {changed_new_candidates} | "
            f"Proactive FontCache additions: {len(proactive_fontcache)} | "
            f"Unknown: {unknown_base}"
        )
    if log_path is not None:
        print(
            "OpenWF 404 recovery: "
            f"Present: {openwf_present} | "
            f"Downloaded: {openwf_downloaded} | "
            f"Repaired: {openwf_repaired} | "
            f"Failed: {openwf_failed}"
        )

    if not full_completion and manifest_skipped:
        if patch_types_only:
            print(
                "NOTE: Some FontCache entries could not be assigned a type in "
                "--patch-types-only mode. The script tried patch-local evidence and the "
                "matching Warframe.x64.exe; no original-base type hints are available "
                "without the base positional path."
            )
        else:
            print(
                "NOTE: Some FontCache entries could not be assigned a type. The script "
                "tried patch-local evidence, the matching Warframe.x64.exe, and base "
                "Cache.Windows type hints."
            )

    incomplete_reasons: list[str] = []
    if manifest_parse_failures:
        incomplete_reasons.append(f"{manifest_parse_failures} manifest parse {_plural(manifest_parse_failures, 'failure')}")
    if manifest_failed:
        incomplete_reasons.append(f"{manifest_failed} manifest repair {_plural(manifest_failed, 'failure')}")
    if openwf_failed:
        incomplete_reasons.append(f"{openwf_failed} OpenWF recovery {_plural(openwf_failed, 'failure')}")
    if manifest_skipped:
        incomplete_reasons.append(f"{manifest_skipped} unresolved manifest {_plural(manifest_skipped, 'type')}")
    if full_completion and unknown_base:
        incomplete_reasons.append(f"{unknown_base} unclassifiable base {_plural(unknown_base, 'asset')}")

    if incomplete_reasons:
        print_warning("Run incomplete: " + " | ".join(incomplete_reasons) + ".")
        return 1

    if section_mode == "only-stripped" and stripped_output_root is not None:
        print(f"Stripped export completed successfully: {stripped_output_root}")
    else:
        print("Repair completed successfully.")
    return 0

def main() -> int:
    double_click_style = len(sys.argv) == 1

    parser = RepairArgumentParser(
        add_help=False,
        allow_abbrev=False,
        description=(
            "Repair an incomplete Warframe update patch created with Ninja Capture "
            "Tool v1.0 for OpenWF against its original Steam base, or run the "
            "FontCache diagnostic mode."
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=str(Path.cwd()),
        help="Warframe/update-patch root (default: current directory)",
    )
    parser.add_argument(
        "base",
        nargs="?",
        type=Path,
        help=(
            "original unupdated Steam-base root (or Cache.Windows directory); "
            "required for normal repair"
        ),
    )
    parser.add_argument(
        "-t",
        "--patch-types-only",
        action="store_true",
        help=(
            "diagnostic FontCache repair from target manifests using patch-local evidence "
            "and matching Warframe.x64.exe mappings; no base path is used"
        ),
    )
    parser.add_argument(
        "-l",
        "--openwf-log",
        type=Path,
        help=(
            "optionally use this exact SpaceNinjaServer/OpenWF trace.log file as a "
            "current-session 404 fallback; logs are not read unless this option is supplied"
        ),
    )
    section_group = parser.add_mutually_exclusive_group()
    section_group.add_argument(
        "-n",
        "--no-stripped",
        action="store_true",
        help="exclude manifest stripped-section assets; service and packed remain enabled",
    )
    section_group.add_argument(
        "-s",
        "--only-stripped",
        action="store_true",
        help=(
            "export changed/new stripped-section assets separately; by default a "
            "timestamped folder is created in the current working directory"
        ),
    )
    parser.add_argument(
        "-o",
        "--stripped-output",
        type=Path,
        help=(
            "with --only-stripped, write to this exact new output folder instead of "
            "creating a timestamped folder in the current working directory"
        ),
    )

    try:
        args = parser.parse_args()

        if args.patch_types_only and args.base is not None:
            parser.error("base path cannot be combined with --patch-types-only")
        if args.patch_types_only and (args.no_stripped or args.only_stripped):
            parser.error("manifest section filters cannot be combined with --patch-types-only")
        if args.stripped_output is not None and not args.only_stripped:
            parser.error("--stripped-output requires --only-stripped")
        if not args.patch_types_only and args.base is None:
            parser.error("base path is required for repair")

        target_root = Path(args.root)

        section_mode = (
            "only-stripped" if args.only_stripped
            else "no-stripped" if args.no_stripped
            else "all"
        )
        with windows_quick_edit_disabled():
            return run(
                target_root,
                args.base,
                patch_types_only=args.patch_types_only,
                openwf_log=args.openwf_log,
                section_mode=section_mode,
                stripped_output=args.stripped_output,
            )
    except KeyboardInterrupt:
        print_warning("Interrupted by user.", file=sys.stderr)
        return 130
    except (RepairError, OSError) as exc:
        print_error(str(exc), file=sys.stderr)
        return 1
    finally:
        if double_click_style:
            try:
                input("\nPress Enter to close...")
            except (EOFError, KeyboardInterrupt):
                pass

if __name__ == "__main__":
    raise SystemExit(main())
