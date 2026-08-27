"""FastAPI application — routes, validation and security middleware."""

from __future__ import annotations

import logging
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from . import base64util, crypto, ratelimit, storage
from .config import Settings

logger = logging.getLogger(__name__)

_HEX_ID = re.compile(r"^[0-9a-f]{32}$")
_STATIC_DIR = Path(__file__).parent / "static"

_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self'; "
        "connect-src 'self'; img-src 'self' data:"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SecretCreate(BaseModel):
    """Validated payload for ``POST /api/v1/secret``."""

    ciphertext: str = Field(min_length=1, description="base64url(iv || AES-GCM ct)")
    ttl_seconds: int | None = Field(default=None, ge=1, description="Desired TTL")
    max_views: int = Field(default=1, ge=1, le=100, description="How many reads before burn")

    @field_validator("ciphertext")
    @classmethod
    def _ciphertext_valid(cls, value: str) -> str:
        if len(value) > 600_000:
            raise ValueError("ciphertext too large")
        try:
            decoded = base64util.decode_b64url(value)
        except Exception as exc:
            raise ValueError("ciphertext must be base64url-encoded bytes") from exc
        if len(decoded) < 13:  # 12-byte IV + at least 1 byte tag/ciphertext
            raise ValueError("ciphertext is too short")
        return value


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def build_app(
    settings: Settings | None = None,
    redis_client: Redis | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = settings or Settings()
    owned_redis = redis_client is None
    redis_conn = redis_client or Redis.from_url(settings.redis_url)
    fernet = settings.fernet()  # fail fast on malformed key

    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # type: ignore[no-untyped-def]
        yield
        if owned_redis:
            try:
                await redis_conn.aclose()
            except Exception:  # nosec B110 - best-effort cleanup on shutdown
                pass

    app = FastAPI(
        title="Vault",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.redis = redis_conn
    app.state.fernet = fernet

    # -- Security & size middleware ----------------------------------------

    @app.middleware("http")
    async def security_and_size_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Early reject based on Content-Length header, before reading the body.
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > settings.max_request_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})

        response = await call_next(request)

        # Never cache secrets or pages that may contain them.
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    # -- Static pages -------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def index_page():  # type: ignore[no-untyped-def]
        return FileResponse(_STATIC_DIR / "index.html")

    @app.get("/s/{secret_id}", include_in_schema=False)
    async def reveal_page(secret_id: str):  # type: ignore[no-untyped-def]
        if not _HEX_ID.fullmatch(secret_id):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(_STATIC_DIR / "reveal.html")

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    # -- Health -------------------------------------------------------------

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request):  # type: ignore[no-untyped-def]
        try:
            await request.app.state.redis.ping()
        except Exception as exc:
            logger.warning("healthz redis ping failed: %s", exc)
            raise HTTPException(status_code=503, detail="unavailable") from exc
        return {"status": "ok"}

    # -- API ---------------------------------------------------------------

    @app.post("/api/v1/secret", status_code=201)
    async def create_secret(payload: SecretCreate, request: Request, response: Response):  # type: ignore[no-untyped-def]
        rl = await ratelimit.enforce_create_rate_limit(request)
        response.headers["X-RateLimit-Limit"] = str(rl.limit)
        response.headers["X-RateLimit-Remaining"] = str(rl.remaining)

        cfg: Settings = request.app.state.settings
        ttl = payload.ttl_seconds if payload.ttl_seconds is not None else cfg.default_ttl_seconds
        ttl = max(cfg.min_ttl_seconds, min(ttl, cfg.max_ttl_seconds))

        secret_id = secrets.token_hex(16)
        key = f"{cfg.key_prefix}{secret_id}"
        try:
            wrapped = crypto.wrap_blob(base64util.decode_b64url(payload.ciphertext), request.app.state.fernet)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid ciphertext payload") from exc
        await storage.create_secret(request.app.state.redis, key, wrapped, ttl, payload.max_views)
        return {"id": secret_id, "path": f"{cfg.base_path}{secret_id}"}

    @app.get("/api/v1/secret/{secret_id}")
    async def read_secret(secret_id: str, request: Request):  # type: ignore[no-untyped-def]
        if not _HEX_ID.fullmatch(secret_id):
            raise HTTPException(status_code=404, detail="Secret does not exist or was destroyed")

        cfg: Settings = request.app.state.settings
        key = f"{cfg.key_prefix}{secret_id}"
        stored = await storage.read_secret(request.app.state.redis, key)
        if stored is None:
            raise HTTPException(status_code=404, detail="Secret does not exist or was destroyed")

        try:
            blob = crypto.unwrap_blob(stored, request.app.state.fernet)
        except ValueError as exc:
            logger.error("unwrap failed for %s: %s", secret_id, exc)
            raise HTTPException(status_code=500, detail="Storage error") from exc

        return {"ciphertext": base64util.encode_b64url(blob)}

    return app


app = build_app()
