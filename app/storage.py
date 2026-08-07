import base64
import json

from redis import exceptions as redis_exceptions
from redis.asyncio import Redis


async def create_secret(r: Redis, key: str, blob: bytes, ttl_seconds: int, max_views: int) -> None:
    payload = json.dumps({"c": base64.b64encode(blob).decode("ascii"), "v": max_views})
    await r.set(key, payload, ex=ttl_seconds)


async def read_secret(r: Redis, key: str) -> bytes | None:
    """Atomically consume one view of a secret, returning the blob or None.

    Uses a WATCH/MULTI/EXEC transaction so concurrent readers can never exceed
    max_views. The key is deleted when the last view is consumed. For the common
    max_views=1 case this is equivalent to an atomic GETDEL.
    """
    while True:
        async with r.pipeline() as pipe:
            try:
                await pipe.watch(key)
                raw = await pipe.get(key)
                if raw is None:
                    return None

                data = json.loads(raw)
                views_left = data["v"] - 1
                if views_left <= 0:
                    pipe.multi()
                    pipe.delete(key)
                else:
                    ttl_ms = await r.pttl(key)
                    data["v"] = views_left
                    pipe.multi()
                    if ttl_ms and ttl_ms > 0:
                        pipe.set(key, json.dumps(data), px=ttl_ms)
                    else:
                        pipe.set(key, json.dumps(data))

                await pipe.execute()
                return base64.b64decode(data["c"])
            except redis_exceptions.WatchError:
                continue
            finally:
                await pipe.reset()
