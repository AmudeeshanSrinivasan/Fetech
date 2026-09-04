"""Isolated full-image validation worker for the media adapter."""

from __future__ import annotations

import io
import json
import sys
import warnings

from fetech.worker_audit import install_worker_audit_hook


def _positive_argument(index: int) -> int:
    try:
        value = int(sys.argv[index])
    except (IndexError, ValueError):
        raise SystemExit(3) from None
    if value <= 0:
        raise SystemExit(3)
    return value


def main() -> int:
    maximum_input_bytes = _positive_argument(1)
    maximum_pixels = _positive_argument(2)
    body = sys.stdin.buffer.read(maximum_input_bytes + 1)
    if not body or len(body) > maximum_input_bytes:
        return 3
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError:
        return 2
    # Pillow discovers decoder plugins lazily. Load the reviewed plugin modules
    # before the audit policy closes arbitrary host-file access.
    Image.init()
    install_worker_audit_hook()
    Image.MAX_IMAGE_PIXELS = maximum_pixels
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    try:
        with Image.open(io.BytesIO(body)) as candidate:
            image_format = (candidate.format or "").casefold()
            width, height = candidate.size
            candidate.verify()
        with Image.open(io.BytesIO(body)) as decoded:
            decoded.load()
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        SyntaxError,
        UnidentifiedImageError,
        ValueError,
    ):
        return 3
    if (
        image_format not in {"gif", "jpeg", "png", "tiff", "webp"}
        or width <= 0
        or height <= 0
        or width * height > maximum_pixels
    ):
        return 3
    sys.stdout.write(
        json.dumps(
            {
                "format": image_format,
                "height": height,
                "width": width,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
