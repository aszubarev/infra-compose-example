"""
Auth demo backend.

This is a tiny resource server. It receives the access token (forwarded by
nginx after oauth2-proxy validated the session), decodes it, and validates the
RS256 signature against Keycloak's public keys (JWKS).

Endpoints (all reachable only through nginx, which enforces authentication):
    GET /api/health   - liveness probe (no token required)
    GET /api/token    - show the raw token and its decoded header/payload
    GET /api/verify   - verify the token signature + iss + exp using JWKS
    GET /api/whoami   - user info from the token and from oauth2-proxy headers
    GET /api/keys     - list the public keys (JWKS) used for validation
"""

import os

import jwt
from fastapi import FastAPI, Header
from jwt import PyJWKClient

REALM = os.getenv("KEYCLOAK_REALM", "demo")
ISSUER = os.getenv(
    "KEYCLOAK_ISSUER",
    "https://keycloak.auth.example.test/realms/demo",
)
JWKS_URL = os.getenv(
    "KEYCLOAK_JWKS_URL",
    f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/certs",
)
ALGORITHMS = ["RS256"]
# Comma separated list of allowed audiences. Empty string disables the
# audience check (Keycloak's default `aud` can be `account` or the client id).
AUDIENCE = os.getenv("TOKEN_AUDIENCE", "")

app = FastAPI(title="auth-demo-backend", version="1.0.0")

_jwks_client = PyJWKClient(JWKS_URL)


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return parts[0] if len(parts) == 1 else None


def _decode_unverified(token: str):
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    return header, payload


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "backend"}


@app.get("/api/token")
def show_token(authorization: str | None = Header(default=None)):
    raw = _bearer_token(authorization)
    if not raw:
        return {"present": False, "error": "No Authorization: Bearer token provided"}
    header, payload = _decode_unverified(raw)
    return {
        "present": True,
        "raw": raw,
        "header": header,
        "payload": payload,
    }


@app.get("/api/verify")
def verify_token(authorization: str | None = Header(default=None)):
    raw = _bearer_token(authorization)
    if not raw:
        return {"valid": False, "error": "No token provided"}

    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(raw)
        header = jwt.get_unverified_header(raw)
        audience = [a for a in AUDIENCE.split(",") if a] or None
        options = {"verify_aud": audience is not None}
        claims = jwt.decode(
            raw,
            signing_key.key,
            algorithms=ALGORITHMS,
            issuer=ISSUER,
            audience=audience,
            options=options,
        )
        return {
            "valid": True,
            "key": {
                "kid": getattr(signing_key, "key_id", None),
                "algorithm": header.get("alg"),
            },
            "claims": claims,
        }
    except Exception as exc:  # noqa: BLE001 - report every failure to the caller
        return {
            "valid": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


@app.get("/api/whoami")
def whoami(
    authorization: str | None = Header(default=None),
    x_auth_request_user: str | None = Header(default=None),
    x_auth_request_email: str | None = Header(default=None),
):
    raw = _bearer_token(authorization)
    claims = _decode_unverified(raw)[1] if raw else {}
    return {
        "from_oauth2_proxy_headers": {
            "user": x_auth_request_user,
            "email": x_auth_request_email,
        },
        "from_access_token": {
            "sub": claims.get("sub"),
            "preferred_username": claims.get("preferred_username"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "given_name": claims.get("given_name"),
            "family_name": claims.get("family_name"),
            "azp": claims.get("azp"),
            "iss": claims.get("iss"),
            "aud": claims.get("aud"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "auth_time": claims.get("auth_time"),
        },
    }


@app.get("/api/keys")
def list_keys():
    import json
    import urllib.request

    with urllib.request.urlopen(JWKS_URL, timeout=10) as resp:  # noqa: S310 - demo
        jwks = json.load(resp)

    keys = []
    for key in jwks.get("keys", []):
        keys.append(
            {
                "kid": key.get("kid"),
                "kty": key.get("kty"),
                "alg": key.get("alg"),
                "use": key.get("use"),
                "key_ops": key.get("key_ops"),
                "n_b64": key.get("n"),
                "e_b64": key.get("e"),
            }
        )
    return {"jwks_url": JWKS_URL, "keys": keys}
