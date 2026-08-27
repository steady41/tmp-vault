import asyncio
import base64
import json

import pytest

from app import base64util
from app.config import Settings
from app.main import build_app


def _b64url(data: bytes) -> str:
    return base64util.encode_b64url(data)


async def _create_secret(client, blob, *, ttl=3600, max_views=1):
    resp = await client.post(
        "/api/v1/secret",
        json={"ciphertext": _b64url(blob), "ttl_seconds": ttl, "max_views": max_views},
    )
    return resp


@pytest.mark.asyncio
async def test_create_and_single_read_roundtrip(client, fake_redis, settings):
    blob = b"\x11" * 64
    resp = await _create_secret(client, blob)
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"]
    assert body["path"] == f"{settings.base_path}{body['id']}"

    raw = await fake_redis.get(f"{settings.key_prefix}{body['id']}")
    stored = json.loads(raw)
    assert stored["v"] == 1
    assert base64.b64decode(stored["c"]).startswith(b"v1|")

    read = await client.get(f"/api/v1/secret/{body['id']}")
    assert read.status_code == 200
    assert read.json()["ciphertext"] == _b64url(blob)

    gone = await client.get(f"/api/v1/secret/{body['id']}")
    assert gone.status_code == 404
    assert await fake_redis.get(f"{settings.key_prefix}{body['id']}") is None


@pytest.mark.asyncio
async def test_max_views_multi_read(client, fake_redis):
    blob = b"\x22" * 32
    resp = await _create_secret(client, blob, max_views=3)
    assert resp.status_code == 201
    secret_id = resp.json()["id"]

    for _ in range(3):
        read = await client.get(f"/api/v1/secret/{secret_id}")
        assert read.status_code == 200
        assert read.json()["ciphertext"] == _b64url(blob)

    assert (await client.get(f"/api/v1/secret/{secret_id}")).status_code == 404


@pytest.mark.asyncio
async def test_ttl_expiry(fake_redis, fernet_key):
    from httpx import ASGITransport, AsyncClient

    fast_expiry = Settings(
        redis_url="redis://127.0.0.1:6379/0",
        fernet_key=fernet_key,
        min_ttl_seconds=1,
        max_ttl_seconds=5,
        create_rate_limit_per_minute=100,
    )
    app = build_app(settings=fast_expiry, redis_client=fake_redis)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await _create_secret(c, b"\x33" * 16, ttl=1)
        assert resp.status_code == 201
        secret_id = resp.json()["id"]

        await asyncio.sleep(1.2)
        gone = await c.get(f"/api/v1/secret/{secret_id}")
        assert gone.status_code == 404


@pytest.mark.asyncio
async def test_ttl_clamped_to_bounds(client, fake_redis, settings):
    resp = await _create_secret(client, b"\x44" * 16, ttl=999_999_999)
    assert resp.status_code == 201
    secret_id = resp.json()["id"]
    ttl = await fake_redis.pttl(f"{settings.key_prefix}{secret_id}")
    assert 0 < ttl <= settings.max_ttl_seconds * 1000


@pytest.mark.asyncio
async def test_unknown_or_invalid_ids_return_404(client):
    assert (await client.get("/api/v1/secret/00000000000000000000000000000000")).status_code == 404
    assert (await client.get("/api/v1/secret/not-a-hex-id")).status_code == 404
    assert (await client.get("/api/v1/secret/short")).status_code == 404


@pytest.mark.asyncio
async def test_invalid_payloads_rejected(client):
    assert (await _create_secret(client, b"")).status_code == 422
    resp = await client.post(
        "/api/v1/secret",
        json={"ciphertext": "!!!not-base64url!!!", "ttl_seconds": 3600, "max_views": 1},
    )
    assert resp.status_code == 422
    resp = await client.post(
        "/api/v1/secret",
        json={"ciphertext": _b64url(b"\x00" * 64), "ttl_seconds": 3600, "max_views": 0},
    )
    assert resp.status_code == 422
    resp = await client.post(
        "/api/v1/secret",
        json={"ciphertext": _b64url(b"\x00" * 64), "ttl_seconds": 3600, "max_views": 101},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_rate_limit_enforced(fake_redis, fernet_key):
    from httpx import ASGITransport, AsyncClient

    limited = Settings(
        redis_url="redis://127.0.0.1:6379/0",
        fernet_key=fernet_key,
        create_rate_limit_per_minute=3,
    )
    app = build_app(settings=limited, redis_client=fake_redis)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        statuses = []
        for _ in range(5):
            resp = await c.post(
                "/api/v1/secret",
                json={"ciphertext": _b64url(b"\x55" * 16), "ttl_seconds": 3600, "max_views": 1},
            )
            statuses.append(resp.status_code)

    assert statuses[:3] == [201, 201, 201]
    assert statuses[3:] == [429, 429]


@pytest.mark.asyncio
async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_security_headers_present(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "no-store" in resp.headers["cache-control"]
    assert "no-cache" in resp.headers["cache-control"]
    assert "Strict-Transport-Security" in resp.headers
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cross-origin-opener-policy"] == "same-origin"


@pytest.mark.asyncio
async def test_server_never_receives_plaintext(client, fake_redis, settings):
    plaintext = b"my_super_password"
    resp = await _create_secret(client, plaintext)
    assert resp.status_code == 201
    secret_id = resp.json()["id"]

    raw = await fake_redis.get(f"{settings.key_prefix}{secret_id}")
    stored = json.loads(raw)
    stored_bytes = base64.b64decode(stored["c"])
    assert plaintext not in stored_bytes
    assert stored_bytes.startswith(b"v1|")
