"""Python-level defense in depth for hostile-data worker processes.

This module deliberately does not call itself a sandbox.  Audit hooks can
constrain Python operations performed by reviewed parsers, but native code can
bypass them and a compromised interpreter can tamper with its own process.
Hostile-input production workers still require a separate operating-system
boundary; Linux required mode supplies it for the covered built-in profiles.
"""

from __future__ import annotations

import os
import stat
import sys
import sysconfig
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

type _PathValue = str | bytes | os.PathLike[str] | os.PathLike[bytes]

_DENIED_EXACT_EVENTS = frozenset(
    {
        "mmap.__new__",
        "os.chdir",
        "os.chmod",
        "os.chown",
        "os.fchdir",
        "os.fork",
        "os.forkpty",
        "os.kill",
        "os.killpg",
        "os.link",
        "os.mkdir",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.symlink",
        "os.system",
        "os.truncate",
        "os.utime",
        "pty.spawn",
        "resource.prlimit",
        "resource.setrlimit",
    }
)
_DENIED_EVENT_PREFIXES = (
    "ctypes.",
    "glob.",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "pathlib.Path.glob",
    "shutil.",
    "socket.",
    "subprocess.",
)
_WRITE_OPEN_FLAGS = (
    os.O_APPEND
    | os.O_CREAT
    | os.O_RDWR
    | os.O_TRUNC
    | os.O_WRONLY
    | getattr(os, "O_TMPFILE", 0)
)
_REVIEWED_NATIVE_EVENTS = frozenset(
    {
        "ctypes.dlopen",
        "ctypes.dlsym",
        "ctypes.string_at",
    }
)
_INITIALIZATION_SCRATCH_EVENTS = frozenset(
    {
        "os.link",
        "os.mkdir",
        "os.remove",
        "os.rmdir",
        "os.utime",
        "shutil.rmtree",
    }
)
_CLEANUP_SCRATCH_EVENTS = frozenset({"os.remove", "os.rmdir"})


@dataclass(slots=True)
class _WorkerAuditState:
    native_initialization_open: bool
    private_scratch_root: str | None
    cleanup_open: bool = False
    cleaned: bool = False


class WorkerAuditGuard:
    """One-way controller for reviewed initialization and scratch cleanup.

    The guard can close the initialization window but cannot reopen it.  Its
    cleanup method temporarily permits only deletion inside the exact private
    scratch tree owned by this worker.
    """

    __slots__ = ("_state",)

    def __init__(self, state: _WorkerAuditState) -> None:
        self._state = state

    def seal_native_initialization(self) -> None:
        """Permanently close the reviewed native initialization window."""

        self._state.native_initialization_open = False

    def cleanup_private_scratch(self) -> None:
        """Remove the exact worker-owned scratch tree after sealing it."""

        self.seal_native_initialization()
        state = self._state
        if state.cleaned or state.private_scratch_root is None:
            return
        root = Path(state.private_scratch_root)
        state.cleanup_open = True
        try:
            if root.exists():
                _remove_private_tree(root)
            state.cleaned = True
            state.private_scratch_root = None
        finally:
            state.cleanup_open = False


def install_worker_audit_hook(
    *,
    additional_read_roots: Iterable[str | os.PathLike[str]] = (),
    allow_reviewed_native_initialization: bool = False,
    private_scratch_root: str | os.PathLike[str] | None = None,
) -> WorkerAuditGuard:
    """Install a fail-closed audit hook for the remainder of this process.

    Read-only imports and package-data access remain available under the
    interpreter's standard-library/site-package roots and the Fetech package.
    All other Python-level file opens, filesystem mutation, network access, and
    process creation are denied.
    """

    scratch_root = _validate_private_scratch_root(private_scratch_root)
    if allow_reviewed_native_initialization != (scratch_root is not None):
        raise ValueError(
            "reviewed native initialization requires one private scratch root"
        )
    explicit_read_roots = _normalize_roots(
        (
            *additional_read_roots,
            *((scratch_root,) if scratch_root is not None else ()),
        )
    )
    allowed_read_roots = _reviewed_read_roots(explicit_read_roots)
    state = _WorkerAuditState(
        native_initialization_open=allow_reviewed_native_initialization,
        private_scratch_root=scratch_root,
    )

    def audit_hook(event: str, arguments: tuple[object, ...]) -> None:
        if (
            state.native_initialization_open
            and _reviewed_initialization_event_allowed(
                event,
                arguments,
                allowed_read_roots=allowed_read_roots,
                private_scratch_root=state.private_scratch_root,
            )
        ):
            return
        if (
            state.cleanup_open
            and state.private_scratch_root is not None
            and _private_scratch_event_allowed(
                event,
                arguments,
                private_scratch_root=state.private_scratch_root,
                allowed_events=_CLEANUP_SCRATCH_EVENTS,
            )
        ):
            return
        _enforce_worker_event(
            event,
            arguments,
            allowed_read_roots=allowed_read_roots,
            # Python's importer must enumerate reviewed standard-library,
            # site-package, Fetech, and model-package directories. Listing
            # remains denied everywhere that is not already readable.
            allowed_listing_roots=allowed_read_roots,
        )

    sys.addaudithook(audit_hook)
    return WorkerAuditGuard(state)


def restrict_worker_import_path(
    *,
    additional_read_roots: Iterable[str | os.PathLike[str]] = (),
) -> None:
    """Remove cwd, missing archives, and other unreviewed import search roots."""

    allowed_roots = _reviewed_read_roots(additional_read_roots)
    retained: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            normalized = _normalize_path(entry)
        except (TypeError, ValueError):
            continue
        if (
            os.path.isdir(normalized)
            and any(_path_is_within(normalized, root) for root in allowed_roots)
            and normalized not in retained
        ):
            retained.append(normalized)
    sys.path[:] = retained


def _reviewed_read_roots(
    additional_read_roots: Iterable[str | os.PathLike[str]] = (),
) -> tuple[str, ...]:
    runtime_paths = sysconfig.get_paths()
    candidates: list[str | os.PathLike[str]] = [
        runtime_paths[key]
        for key in ("stdlib", "platstdlib", "purelib", "platlib")
        if runtime_paths.get(key)
    ]
    candidates.append(Path(__file__).resolve().parent)
    candidates.extend(additional_read_roots)
    return _normalize_roots(candidates)


def _normalize_roots(
    candidates: Iterable[str | os.PathLike[str]],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _normalize_path(candidate)
                for candidate in candidates
                if os.fspath(candidate)
            }
        )
    )


def _validate_private_scratch_root(
    candidate: str | os.PathLike[str] | None,
) -> str | None:
    if candidate is None:
        return None
    try:
        supplied = Path(candidate)
        if supplied.is_symlink():
            raise ValueError("private worker scratch cannot be a symbolic link")
        normalized = _normalize_path(supplied)
        metadata = os.stat(normalized, follow_symlinks=False)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("private worker scratch is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or normalized == os.path.abspath(os.sep)
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("private worker scratch must be an owner-only directory")
    return normalized


def _reviewed_initialization_event_allowed(
    event: str,
    arguments: tuple[object, ...],
    *,
    allowed_read_roots: tuple[str, ...],
    private_scratch_root: str | None,
) -> bool:
    if event in _REVIEWED_NATIVE_EVENTS:
        return _reviewed_native_event_allowed(
            event,
            arguments,
            allowed_read_roots=allowed_read_roots,
        )
    if private_scratch_root is None:
        return False
    if event == "open":
        return _private_scratch_write_allowed(
            arguments,
            private_scratch_root=private_scratch_root,
        )
    return _private_scratch_event_allowed(
        event,
        arguments,
        private_scratch_root=private_scratch_root,
        allowed_events=_INITIALIZATION_SCRATCH_EVENTS,
    )


def _reviewed_native_event_allowed(
    event: str,
    arguments: tuple[object, ...],
    *,
    allowed_read_roots: tuple[str, ...],
) -> bool:
    if event == "ctypes.dlopen":
        if len(arguments) != 1:
            return False
        library = arguments[0]
        if library is None:
            return True
        return _reviewed_absolute_path(library, allowed_read_roots)
    if event == "ctypes.dlsym":
        if len(arguments) != 2:
            return False
        handle_name = getattr(arguments[0], "_name", None)
        symbol = arguments[1]
        if (
            not isinstance(symbol, str)
            or not 1 <= len(symbol) <= 256
            or not symbol.isascii()
            or any(
                not (character.isalnum() or character == "_")
                for character in symbol
            )
        ):
            return False
        return handle_name is None or _reviewed_absolute_path(
            handle_name,
            allowed_read_roots,
        )
    if event == "ctypes.string_at":
        return (
            len(arguments) == 2
            and isinstance(arguments[0], int)
            and not isinstance(arguments[0], bool)
            and arguments[0] > 0
            and arguments[1] == -1
        )
    return False


def _reviewed_absolute_path(
    value: object,
    allowed_roots: tuple[str, ...],
) -> bool:
    if not isinstance(value, (str, bytes, os.PathLike)):
        return False
    try:
        raw_path = os.fsdecode(os.fspath(value))
        if not os.path.isabs(raw_path):
            return False
        candidate = _normalize_path(value)
    except (TypeError, ValueError):
        return False
    return any(_path_is_within(candidate, root) for root in allowed_roots)


def _private_scratch_write_allowed(
    arguments: tuple[object, ...],
    *,
    private_scratch_root: str,
) -> bool:
    if (
        not arguments
        or isinstance(arguments[0], int)
        or not isinstance(arguments[0], (str, bytes, os.PathLike))
    ):
        return False
    mode = arguments[1] if len(arguments) > 1 else None
    flags = arguments[2] if len(arguments) > 2 else None
    write_requested = (
        isinstance(mode, str) and any(marker in mode for marker in "wax+")
    ) or (isinstance(flags, int) and bool(flags & _WRITE_OPEN_FLAGS))
    return write_requested and _absolute_path_is_within(
        arguments[0],
        private_scratch_root,
    )


def _private_scratch_event_allowed(
    event: str,
    arguments: tuple[object, ...],
    *,
    private_scratch_root: str,
    allowed_events: frozenset[str],
) -> bool:
    if event not in allowed_events or not arguments:
        return False
    if event == "os.link":
        return (
            len(arguments) >= 2
            and _absolute_path_is_within(arguments[0], private_scratch_root)
            and _absolute_path_is_within(arguments[1], private_scratch_root)
        )
    return _absolute_path_is_within(arguments[0], private_scratch_root)


def _absolute_path_is_within(value: object, root: str) -> bool:
    if not isinstance(value, (str, bytes, os.PathLike)):
        return False
    try:
        raw_path = os.fsdecode(os.fspath(value))
        return os.path.isabs(raw_path) and _path_is_within(
            _normalize_path(value),
            root,
        )
    except (TypeError, ValueError):
        return False


def _remove_private_tree(root: Path) -> None:
    with os.scandir(root) as entries:
        children = list(entries)
    for entry in children:
        child = root / entry.name
        if entry.is_dir(follow_symlinks=False):
            _remove_private_tree(child)
        else:
            os.unlink(child)
    os.rmdir(root)


def _enforce_worker_event(
    event: str,
    arguments: tuple[object, ...],
    *,
    allowed_read_roots: tuple[str, ...],
    allowed_listing_roots: tuple[str, ...] = (),
) -> None:
    if event == "open":
        _enforce_open(arguments, allowed_read_roots=allowed_read_roots)
        return
    if event in {"os.listdir", "os.scandir"}:
        _enforce_directory_listing(
            arguments,
            allowed_listing_roots=allowed_listing_roots,
        )
        return
    if (
        event in _DENIED_EXACT_EVENTS
        or event.startswith(_DENIED_EVENT_PREFIXES)
    ):
        raise PermissionError("worker operation denied by Python audit policy")


def _enforce_directory_listing(
    arguments: tuple[object, ...],
    *,
    allowed_listing_roots: tuple[str, ...],
) -> None:
    if (
        not arguments
        or not isinstance(arguments[0], (str, bytes, os.PathLike))
        or os.fspath(arguments[0]) in {"", b""}
    ):
        raise PermissionError("worker directory listing denied by Python audit policy")
    try:
        candidate = _normalize_path(arguments[0])
    except (TypeError, ValueError):
        raise PermissionError(
            "worker directory listing denied by Python audit policy"
        ) from None
    if not any(
        _path_is_within(candidate, root) for root in allowed_listing_roots
    ):
        raise PermissionError("worker directory listing denied by Python audit policy")


def _enforce_open(
    arguments: tuple[object, ...],
    *,
    allowed_read_roots: tuple[str, ...],
) -> None:
    if (
        not arguments
        or isinstance(arguments[0], int)
        or not isinstance(arguments[0], (str, bytes, os.PathLike))
    ):
        raise PermissionError("worker file access denied by Python audit policy")
    try:
        candidate = _normalize_path(arguments[0])
    except (TypeError, ValueError):
        raise PermissionError(
            "worker file access denied by Python audit policy"
        ) from None

    mode = arguments[1] if len(arguments) > 1 else None
    flags = arguments[2] if len(arguments) > 2 else None
    if (
        (isinstance(mode, str) and any(marker in mode for marker in "wax+"))
        or (isinstance(flags, int) and flags & _WRITE_OPEN_FLAGS)
        or not any(
            _path_is_within(candidate, root) for root in allowed_read_roots
        )
    ):
        raise PermissionError("worker file access denied by Python audit policy")


def _normalize_path(value: _PathValue) -> str:
    path = os.fsdecode(os.fspath(value))
    if "\x00" in path:
        raise ValueError("NUL is forbidden in worker file paths")
    return os.path.realpath(os.path.abspath(path))


def _path_is_within(candidate: str, root: str) -> bool:
    try:
        return os.path.commonpath((candidate, root)) == root
    except ValueError:
        return False
