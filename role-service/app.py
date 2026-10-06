"""
External role service — the single source of truth for user roles.

Roles are read from a JSON file (mounted as a volume) on EVERY request, so
editing the file on the host takes effect immediately, without restarting the
container.

Keyed by username (the user chose username as the employee identifier).
"""
import json
import os

from fastapi import FastAPI, HTTPException

ROLES_FILE = os.getenv("ROLES_FILE", "/app/data/roles.json")

app = FastAPI(title="role-service")


def _load_roles() -> dict:
    """Read the roles file on every call so host edits are picked up at once."""
    try:
        with open(ROLES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"roles file not found: {ROLES_FILE}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"invalid JSON in roles file: {e}")

    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="roles file must be a JSON object {username: [roles]}")
    return data


@app.get("/health")
def health():
    return {"status": "ok", "service": "role-service"}


@app.get("/users/{username}/roles")
def get_roles(username: str):
    roles_map = _load_roles()
    roles = roles_map.get(username)
    if roles is None:
        # Unknown user -> 404. The Keycloak mapper treats any non-200 as
        # "no roles", so this is fail-closed for authorization.
        raise HTTPException(status_code=404, detail=f"unknown user: {username}")
    if not isinstance(roles, list):
        raise HTTPException(status_code=500, detail=f"roles for '{username}' must be a list")
    return {"username": username, "roles": roles}
