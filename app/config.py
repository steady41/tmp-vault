from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, overridable via env vars with the VAULT_ prefix."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="VAULT_", extra="ignore")

    redis_url: str = "redis://127.0.0.1:6379/0"
    fernet_key: str = ""

    key_prefix: str = "secret:"
    base_path: str = "/s/"

    default_ttl_seconds: int = 86400
    min_ttl_seconds: int = 60
    max_ttl_seconds: int = 604800
    max_request_bytes: int = 100_000
    create_rate_limit_per_minute: int = 10
    trust_proxy: bool = False

    def fernet(self) -> Fernet | None:
        """Return a Fernet instance for the app-level key, or None if unset.

        Raises ValueError at startup when the configured key is malformed so the
        server fails fast instead of corrupting stored blobs.
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
