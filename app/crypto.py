from cryptography.fernet import Fernet, InvalidToken

_PLAIN = b"v0|"
_ENCRYPTED = b"v1|"


def wrap_blob(blob: bytes, fernet: Fernet | None) -> bytes:
    """Optionally encrypt the stored blob with the app-level Fernet key.

    The blob is already ciphertext from the client's perspective, so this is
    defense-in-depth: even a Redis dump is useless without the app key and the
    client key that lived only in the URL fragment.
    """
    if fernet is None:
        return _PLAIN + blob
    return _ENCRYPTED + fernet.encrypt(blob)


def unwrap_blob(blob: bytes, fernet: Fernet | None) -> bytes:
    """Reverse wrap_blob; raises ValueError on version or key mismatches."""
    version, payload = blob[:3], blob[3:]
    if version == _PLAIN:
        return payload
    if version == _ENCRYPTED:
        if fernet is None:
            raise ValueError("stored blob is encrypted but no VAULT_FERNET_KEY is configured")
        try:
            return fernet.decrypt(payload)
        except InvalidToken as exc:
            raise ValueError("cannot decrypt stored blob: bad key or corrupted data") from exc
    raise ValueError(f"unknown stored blob version: {version!r}")
