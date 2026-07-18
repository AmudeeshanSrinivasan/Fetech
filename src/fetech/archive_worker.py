"""Ephemeral stdin/stdout worker for hostile ZIP and TAR inputs."""

from __future__ import annotations

import base64
import binascii
import json
import sys
from typing import NoReturn

from fetech.adapters.archive import ArchiveLimits, _extract_members

MAX_ARCHIVE_WORKER_STDIN_BYTES = 70_000_000
_LIMIT_FIELDS = frozenset(
    {"maximum_members", "maximum_expanded", "maximum_ratio"}
)


def main() -> int:
    try:
        payload = _read_payload()
        body, limits = _validate_payload(payload)
        # ZIP filenames without the UTF-8 flag use CP437. Load that reviewed
        # codec before the audit hook closes filesystem reads.
        b"archive-worker".decode("cp437")
        sys.addaudithook(_deny_runtime_side_effects)
        members = _extract_members(
            body,
            maximum_members=limits.maximum_members,
            maximum_expanded=limits.maximum_expanded,
            maximum_ratio=limits.maximum_ratio,
        )
        sys.stdout.write(
            json.dumps(
                {
                    "members": [
                        {
                            "name": name,
                            "body": base64.b64encode(content).decode("ascii"),
                        }
                        for name, content in members
                    ]
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        return 0
    except Exception:
        sys.stdout.write(json.dumps({"error": "archive_parse_failed"}, separators=(",", ":")))
        return 1


def _read_payload() -> object:
    encoded = sys.stdin.buffer.read(MAX_ARCHIVE_WORKER_STDIN_BYTES + 1)
    if len(encoded) > MAX_ARCHIVE_WORKER_STDIN_BYTES:
        _fail("archive worker input exceeded its hard byte limit")
    try:
        return json.loads(encoded, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("archive worker input is not strict JSON") from exc


def _validate_payload(payload: object) -> tuple[bytes, ArchiveLimits]:
    if not isinstance(payload, dict) or set(payload) != {"body", "limits"}:
        raise ValueError("archive worker payload schema is invalid")
    encoded_body = payload["body"]
    raw_limits = payload["limits"]
    if not isinstance(encoded_body, str):
        raise ValueError("archive worker body must be base64 text")
    try:
        body = base64.b64decode(encoded_body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("archive worker body is not valid base64") from exc
    limits = _parse_limits(raw_limits)
    if len(body) > limits.maximum_expanded:
        # The normal parent input bound is usually tighter. This hard worker
        # check prevents an independently invoked worker from accepting an
        # input larger than its total expanded-data budget.
        raise ValueError("archive worker body exceeds its hard byte limit")
    return body, limits


def _parse_limits(value: object) -> ArchiveLimits:
    if not isinstance(value, dict) or set(value) != _LIMIT_FIELDS:
        raise ValueError("archive worker limits schema is invalid")
    members = value["maximum_members"]
    expanded = value["maximum_expanded"]
    ratio = value["maximum_ratio"]
    if (
        isinstance(members, bool)
        or not isinstance(members, int)
        or members <= 0
        or isinstance(expanded, bool)
        or not isinstance(expanded, int)
        or expanded <= 0
        or isinstance(ratio, bool)
        or not isinstance(ratio, int | float)
        or ratio < 1
    ):
        raise ValueError("archive worker limits are invalid")
    return ArchiveLimits(members, expanded, float(ratio))


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _deny_runtime_side_effects(event: str, arguments: tuple[object, ...]) -> None:
    """Forbid parser-triggered filesystem, network, and process access."""

    del arguments
    if (
        event == "open"
        or event.startswith("socket.")
        or event.startswith("subprocess.")
        or event.startswith("os.spawn")
        or event in {"os.system", "os.posix_spawn", "pty.spawn"}
    ):
        raise PermissionError("archive worker side effects are forbidden")


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


if __name__ == "__main__":
    raise SystemExit(main())
