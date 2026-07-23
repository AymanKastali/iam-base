# iam-base

Standalone Authentication & Identity Management service: email + password
registration/login, JWT access + refresh tokens, and a JWKS endpoint so
consuming services can verify tokens themselves. See
`docs/design/iam-base-service.md` for the full design rationale.

## Prerequisites

- Docker and Docker Compose

## Generating signing keys

The service signs access tokens with an RSA private key, and can hold more
than one at a time (see "Rotating the signing key" below). Each key lives
in its own PEM file inside a keys directory, named `<key-id>.pem`:

```bash
mkdir -p deployments/keys
openssl genrsa -traditional -out deployments/keys/1.pem 2048
```

`-traditional` is required: the service expects PKCS1-encoded keys, and
recent OpenSSL versions default to PKCS8.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | no | `8080` | HTTP port the server listens on |
| `DATABASE_URL` | yes | — | Postgres connection string |
| `JWT_KEYS_DIR` | yes | — | Directory of `<key-id>.pem` RSA private keys |
| `JWT_ACTIVE_KEY_ID` | no | `1` | Which key in `JWT_KEYS_DIR` signs new tokens |
| `ACCESS_TOKEN_TTL` | no | `15m` | Access token lifetime (Go duration syntax) |
| `REFRESH_TOKEN_TTL` | no | `720h` | Refresh token lifetime (Go duration syntax) |
| `RATE_LIMIT_RPS` | no | `5` | Requests per second allowed per client IP |
| `RATE_LIMIT_BURST` | no | `10` | Burst size allowed per client IP |

## Running

```bash
cd deployments
docker compose up --build
```

This builds the image, starts Postgres, runs pending migrations
automatically on boot, and starts the identity service on `:8080`.

## Rotating the signing key

1. Generate a new key into the same directory, e.g.
   `openssl genrsa -traditional -out deployments/keys/2.pem 2048`.
2. Set `JWT_ACTIVE_KEY_ID=2` and redeploy. `/.well-known/jwks.json` now
   publishes both keys, so tokens already issued under key `1` still verify.
3. Once `REFRESH_TOKEN_TTL` has fully elapsed since the last token was
   issued under key `1` (so nothing signed under it can still be
   presented), delete `deployments/keys/1.pem` and redeploy again to
   retire it from the published JWKS.

## API reference

The service exposes live, code-first OpenAPI docs once running:

- Swagger UI: `http://localhost:8080/docs`
- OpenAPI spec: `http://localhost:8080/openapi.json`
