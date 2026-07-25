"""Bounded static-file access and container magic validation."""

from __future__ import annotations

from pathlib import Path

MAX_STATIC_FILE_SIZE = 100 * 1024 * 1024


class MagicError(ValueError):
    """A static sample is unsupported, malformed, or over the size limit."""


def read_static_file(
    path: str | Path,
    *,
    expected_magic: tuple[bytes, ...] = (),
) -> bytes:
    """Read at most 100 MiB after checking the file header and size."""
    resolved = Path(path).expanduser().resolve()
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise MagicError(f"cannot stat binary: {resolved}: {exc}") from exc
    if size > MAX_STATIC_FILE_SIZE:
        raise MagicError(
            f"binary exceeds 100 MiB static-analysis limit: {size} bytes"
        )
    try:
        with resolved.open("rb") as stream:
            header = stream.read(64)
            if expected_magic and not any(
                header.startswith(magic) for magic in expected_magic
            ):
                expected = " or ".join(magic.hex() for magic in expected_magic)
                raise MagicError(f"unsupported file magic; expected {expected}")
            stream.seek(0)
            return stream.read(MAX_STATIC_FILE_SIZE + 1)
    except MagicError:
        raise
    except OSError as exc:
        raise MagicError(f"cannot read binary: {resolved}: {exc}") from exc


def validate_bytes(
    data: bytes,
    *,
    expected_magic: tuple[bytes, ...],
) -> None:
    """Apply the same size and magic bounds to an in-memory fixture."""
    if len(data) > MAX_STATIC_FILE_SIZE:
        raise MagicError(
            f"binary exceeds 100 MiB static-analysis limit: {len(data)} bytes"
        )
    if not any(data.startswith(magic) for magic in expected_magic):
        expected = " or ".join(magic.hex() for magic in expected_magic)
        raise MagicError(f"unsupported file magic; expected {expected}")
