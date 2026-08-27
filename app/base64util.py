"""Unpadded base64url helpers — the wire format for ciphertext blobs."""

from __future__ import annotations

import base64


def decode_b64url(value: str) -> bytes:
    """Decode an unpadded base64url string into raw bytes.

    Whitespace is stripped; ``-``/``_`` are treated as ``+``/``/``.
    Raises ``binascii.Error`` / ``ValueError`` on malformed input.
    """
    s = value.strip().replace("-", "+").replace("_", "/")
    # Add required ``=`` padding before stdlib validation.
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


def encode_b64url(data: bytes) -> str:
    """Encode raw bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
