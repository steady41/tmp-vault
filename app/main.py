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

_HEX_ID = re.compile(r"^[0-9a-f]{32}$")
_STATIC_DIR = Path(__file__).parent / "static"

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; img-src 'self' data:"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecretCreate(BaseModel):
    ciphertext: str = Field(min_length=1)
    ttl_seconds: int | None = None
    max_views: int = Field(default=1, ge=1, le=100)

    @field_validator("ciphertext")
    @classmethod
    def _ciphertext_valid(cls, value: str) -> str:
        if len(value) > 600_000:
            raise ValueError("ciphertext too large")
        try:
            decoded = base64util.decode_b64url(value)
        except Exception as exc:
            raise ValueError("ciphertext must be base64url-encoded bytes") from exc
        if len(decoded) < 12:
            raise ValueError("ciphertext is too short")
        return value


def build_app(settings: Settings | None = None, redis_client: Redis | None = None) -> FastAPI:
    settings = settings or Settings()
    owned_redis = redis_client is None
    redis_conn = redis_client or Redis.from_url(settings.redis_url)

    # Fail fast on a malformed app-level Fernet key.
    fernet = settings.fernet()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        if owned_redis:
            await redis_conn.aclose()

    app = FastAPI(title="Vault", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.redis = redis_conn
    app.state.fernet = fernet

    @app.middleware("http")
    async def security_and_size_middleware(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > settings.max_request_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        for key, value in _SECURITY_HEADERS.items():
            if key not in response.headers:
                response.headers[key] = value
        return response

    @app.get("/", include_in_schema=False)
    async def index_page():
        return FileResponse(_STATIC_DIR / "index.html")

    @app.get("/s/{secret_id}", include_in_schema=False)
    async def reveal_page(secret_id: str):
        if not _HEX_ID.fullmatch(secret_id):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(_STATIC_DIR / "reveal.html")

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request):
        try:
            await request.app.state.redis.ping()
        except Exception:
            raise HTTPException(status_code=503, detail="unavailable")
        return {"status": "ok"}

    @app.post("/api/v1/secret", status_code=201)
    async def create_secret(payload: SecretCreate, request: Request, response: Response):
        rl = await ratelimit.enforce_create_rate_limit(request)
        response.headers["X-RateLimit-Limit"] = str(rl.limit)
        response.headers["X-RateLimit-Remaining"] = str(rl.remaining)

        settings = request.app.state.settings
        ttl = payload.ttl_seconds or settings.default_ttl_seconds
        ttl = max(settings.min_ttl_seconds, min(ttl, settings.max_ttl_seconds))

        secret_id = secrets.token_hex(16)
        key = f"{settings.key_prefix}{secret_id}"
        wrapped = crypto.wrap_blob(base64util.decode_b64url(payload.ciphertext), request.app.state.fernet)
        await storage.create_secret(request.app.state.redis, key, wrapped, ttl, payload.max_views)
        # The decryption key is appended client-side as a URL fragment and is
        # never seen or stored by the server.
        return {"id": secret_id, "path": f"{settings.base_path}{secret_id}"}

    @app.get("/api/v1/secret/{secret_id}")
    async def read_secret(secret_id: str, request: Request):
        if not _HEX_ID.fullmatch(secret_id):
            raise HTTPException(status_code=404, detail="Secret does not exist or was destroyed")

        settings = request.app.state.settings
        key = f"{settings.key_prefix}{secret_id}"
        stored = await storage.read_secret(request.app.state.redis, key)
        if stored is None:
            raise HTTPException(status_code=404, detail="Secret does not exist or was destroyed")

        try:
            blob = crypto.unwrap_blob(stored, request.app.state.fernet)
        except ValueError as exc:
            raise HTTPException(status_code=500, detail="Storage error") from exc

        return {"ciphertext": base64util.encode_b64url(blob)}

    return app


app = build_app()
