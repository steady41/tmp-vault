# Vault — zero-knowledge, single-use secret sharing

Share a password, token, or short message through a link that self-destructs
after the first read (or after a TTL). The server is **zero-knowledge**: the
plaintext and the encryption key never leave the browser.

## Security model

1. **Client-side encryption (true zero-knowledge).** The browser generates a
   256-bit AES-GCM key, encrypts the secret with Web Crypto, and sends only the
   ciphertext (`iv || ct || tag`, base64url) to the server. The key is placed in
   the URL **fragment** (`/s/{id}#{key}`) by the browser — fragments are never
   sent in HTTP requests, so the server, Redis, and the reverse proxy never see
   it.

2. **Ephemeral storage.** Redis stores the ciphertext under `secret:{id}` with a
   TTL (Redis expires it automatically). Reads use an atomic
   `WATCH`/`MULTI`/`EXEC` transaction that decrements the view counter and
   `DEL`s the key at zero — a secret cannot be read twice, even under
   concurrency.

3. **Defense-in-depth at rest.** With `VAULT_FERNET_KEY` set, the stored blob is
   additionally wrapped with Fernet. Even a full Redis dump is useless without
   both the app key and the per-secret client key.

4. **Hardening.** `no-store` caching, strict CSP/HSTS/nosniff/referrer headers,
   request-size limits, per-IP rate limiting, hidden OpenAPI docs.

## Layout

```
app/
  main.py        FastAPI app, routes, security middleware
  config.py      Settings (VAULT_* env vars)
  crypto.py      Fernet wrap/unwrap of stored blobs
  storage.py     Redis create + atomic read (WATCH/EXEC)
  ratelimit.py   per-IP create rate limiting
  base64util.py  base64url helpers
  static/        frontend (index, reveal, client-side AES-GCM)
tests/           pytest suite (runs against fakeredis)
```

## API

| Method | Path                     | Body / Notes                                 |
| ------ | ------------------------ | -------------------------------------------- |
| POST   | `/api/v1/secret`         | `{"ciphertext", "ttl_seconds"?, "max_views"?}` → `201 {"id", "path"}` |
| GET    | `/api/v1/secret/{id}`    | Atomic read+delete → `200 {"ciphertext"}` or `404` |
| GET    | `/healthz`               | Redis liveness check                         |

- `ttl_seconds` is clamped to `VAULT_MIN_TTL_SECONDS`..`VAULT_MAX_TTL_SECONDS`
  (default 60..604800); defaults to `VAULT_DEFAULT_TTL_SECONDS` (86400).
- `max_views` must be 1..100; the key is destroyed when the counter reaches 0.
- Create requests are limited to `VAULT_CREATE_RATE_LIMIT_PER_MINUTE` (10) per IP.

## Running locally (tests)

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

## Running the app

```sh
cp .env.example .env
uvicorn app.main:app --reload          # needs a local Redis on 6379
```

## Configuration

All settings are `VAULT_`-prefixed env vars (see `app/config.py` and
`.env.example`).

| Variable                              | Default          | Purpose                                  |
| ------------------------------------- | ---------------- | ---------------------------------------- |
| `VAULT_REDIS_URL`                     | `redis://127.0.0.1:6379/0` | Redis connection            |
| `VAULT_FERNET_KEY`                    | *(empty)*        | Optional app-level encryption of stored blobs |
| `VAULT_DEFAULT_TTL_SECONDS`           | `86400`          | Default secret TTL                      |
| `VAULT_MIN_TTL_SECONDS`               | `60`             | Lower TTL clamp                          |
| `VAULT_MAX_TTL_SECONDS`               | `604800`         | Upper TTL clamp                          |
| `VAULT_CREATE_RATE_LIMIT_PER_MINUTE`  | `10`             | Create requests / IP / minute            |
| `VAULT_MAX_REQUEST_BYTES`             | `100000`         | Reject larger request bodies (413)       |
| `VAULT_TRUST_PROXY`                   | `false`          | Honor `X-Forwarded-For` for rate limiting |

Generate a Fernet key:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## License

[MIT](LICENSE) © Dreadless
