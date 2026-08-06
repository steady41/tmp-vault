import fakeredis.aioredis
import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import build_app


@pytest.fixture
def fernet_key() -> str:
    return Fernet.generate_key().decode("ascii")


@pytest.fixture
def settings(fernet_key) -> Settings:
    return Settings(
        redis_url="redis://127.0.0.1:6379/0",
        fernet_key=fernet_key,
        create_rate_limit_per_minute=100,
    )


@pytest.fixture
def fake_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=False)


@pytest.fixture
def app(settings, fake_redis):
    return build_app(settings=settings, redis_client=fake_redis)


@pytest.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
