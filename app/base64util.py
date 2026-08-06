import base64


def decode_b64url(value: str) -> bytes:
    """Decode a base64url string (padding optional) into raw bytes."""
    s = value.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


def encode_b64url(data: bytes) -> str:
    """Encode raw bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
