"""Atomic Redis operations for single-use secrets."""

from __future__ import annotations

import base64
import json
import logging

from redis import exceptions as redis_exceptions
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


async def create_secret(
    r: Redis,
    key: str,
    blob: bytes,
    ttl_seconds: int,
    max_views: int,
) -> None:
    """Persist a wrapped ciphertext blob with TTL and view counter.

    The payload is JSON: ``{"c": <std-b64 of wrapped blob>, "v": max_views}``.
    """
    payload = json.dumps({"c": base64.b64encode(blob).decode("ascii"), "v": max_views})
    await r.set(key, payload, ex=ttl_seconds)


async def read_secret(r: Redis, key: str) -> bytes | None:
    """Atomically consume one view of a secret.

    Returns the wrapped blob or ``None`` when the key is missing or
    exhausted. Uses ``WATCH`` / ``MULTI`` / ``EXEC`` so concurrent readers
    can never exceed ``max_views``. For ``max_views == 1`` this is
    equivalent to an atomic ``GETDEL``.

    Corrupted payloads are treated as destroyed (key deleted, ``None``
    returned) to avoid leaking half-written state.
    """
    while True:
        async with r.pipeline() as pipe:
            try:
                await pipe.watch(key)
                raw = await pipe.get(key)
                if raw is None:
                    return None

                try:
                    data = json.loads(raw)
                    b64_blob: str = data["c"]
                    views_left: int = int(data["v"]) - 1
                except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                    logger.warning("corrupted secret payload for %s: %s", key, exc)
                    pipe.multi()
                    pipe.delete(key)
                    await pipe.execute()
                    return None

                if views_left <= 0:
                    pipe.multi()
                    pipe.delete(key)
                else:
                    # Keep the original TTL untouched.
                    # Redis >= 6.0 supports KEEPTTL — preserves whatever TTL
                    # the key already has without re-reading it. Falls back to
                    # without expiry if the key had none (persist).
                    data["v"] = views_left
                    pipe.multi()
                    try:
                        # redis-py 4.6+ exposes keepttl kwarg
                        pipe.set(key, json.dumps(data), keepttl=True)  # type: ignore[call-arg]
                    except TypeError:
                        pipe.set(key, json.dumps(data))

                await pipe.execute()
                return base64.b64decode(b64_blob)

            except redis_exceptions.WatchError:
                # Another client modified the key — retry.
                continue
            finally:
                try:
                    await pipe.reset()
                except Exception:
                    pass
