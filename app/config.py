"""Application settings — all overridable via ``VAULT_`` env vars."""

from __future__ import annotations

from cryptography.fernet import Fernet
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application configuration.

    Every field can be overridden with an environment variable prefixed with
    ``VAULT_`` (e.g. ``VAULT_REDIS_URL``). An optional ``.env`` file in the
    working directory is also read.
    """

    model_config = SettingsConfigDict(env_file=".env", env_prefix="VAULT_", extra="ignore")

    redis_url: str = Field(default="redis://127.0.0.1:6379/0", description="Redis connection URL")
    fernet_key: str = Field(default="", description="Optional app-level Fernet key (base64 32 bytes)")

    key_prefix: str = Field(default="secret:", description="Redis key prefix for secrets")
    base_path: str = Field(default="/s/", description="Public path prefix for reveal links")

    default_ttl_seconds: int = Field(default=86400, ge=1, description="Default TTL for new secrets")
    min_ttl_seconds: int = Field(default=60, ge=1, description="Minimum TTL clamp")
    max_ttl_seconds: int = Field(default=604800, ge=1, description="Maximum TTL clamp")

    max_request_bytes: int = Field(default=100_000, ge=1024, le=10_000_000)
    create_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    trust_proxy: bool = Field(default=False, description="Honor X-Forwarded-For when behind a trusted proxy")

    @field_validator("max_ttl_seconds")
    @classmethod
    def _ttl_bounds_consistent(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        data = info.data
        if "min_ttl_seconds" in data and v < data["min_ttl_seconds"]:
            raise ValueError("VAULT_MAX_TTL_SECONDS must be >= VAULT_MIN_TTL_SECONDS")
        return v

    @field_validator("default_ttl_seconds")
    @classmethod
    def _default_within_bounds(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        data = info.data
        min_v = data.get("min_ttl_seconds")
        max_v = data.get("max_ttl_seconds")
        # Only validate when both bounds are already known; during model
        # construction order isn't guaranteed, so be lenient.
        if min_v is not None and max_v is not None and not (min_v <= v <= max_v):
            raise ValueError("VAULT_DEFAULT_TTL_SECONDS must be within [min, max]")
        return v

    def fernet(self) -> Fernet | None:
        """Return a ``Fernet`` instance or ``None`` when no app key is configured.

        Raises ``ValueError`` at startup when the configured key is malformed so
        the server fails fast instead of corrupting stored blobs.
        """
        if not self.fernet_key:
            return None
        try:
            return Fernet(self.fernet_key.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "VAULT_FERNET_KEY is not a valid Fernet key "
                "(generate one with Fernet.generate_key())"
            ) from exc
