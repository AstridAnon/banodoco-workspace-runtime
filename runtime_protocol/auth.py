from __future__ import annotations

import json
import secrets
from pathlib import Path

from .errors import AuthorizationError, ValidationError


class CredentialStore:
    """Owner-only bearer credentials with explicit actor scopes."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def provision(self, actor: str, scopes: list[str], *, metadata: dict | None = None, rotate: bool = False) -> tuple[str, Path]:
        if not actor or "/" in actor or ".." in actor:
            raise ValidationError("invalid actor")
        expected_scopes = sorted(set(str(scope) for scope in scopes))
        path = self.root / f"{actor}.token"
        metadata_path = self.root / f"{actor}.json"
        # Reuse a durable credential only when its actor, scope set, and file
        # ownership are exactly the requested contract.  Runtime relaunches
        # must not rotate the worker identity behind a surviving host process,
        # while an old/broadened credential must never be silently retained.
        try:
            if not rotate and (path.is_file() and not path.is_symlink()
                    and metadata_path.is_file() and not metadata_path.is_symlink()
                    and path.stat().st_mode & 0o777 == 0o600
                    and metadata_path.stat().st_mode & 0o777 == 0o600):
                current_token = path.read_text(encoding="utf-8").strip()
                current = json.loads(metadata_path.read_text(encoding="utf-8"))
                if (current_token and isinstance(current, dict)
                        and current.get("actor") == actor
                        and sorted(set(current.get("scopes", []))) == expected_scopes):
                    return current_token, path
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
            pass
        if path.is_symlink() or metadata_path.is_symlink():
            raise ValidationError("credential path must not be a symlink")
        token = secrets.token_urlsafe(32)
        path.write_text(token, encoding="utf-8")
        path.chmod(0o600)
        value = {"actor": actor, "scopes": expected_scopes}
        if metadata:
            value.update(metadata)
        metadata_path.write_text(json.dumps(value), encoding="utf-8")
        metadata_path.chmod(0o600)
        return token, path

    def provision_static(self, actor: str, token: str, scopes: list[str]) -> Path:
        """Install a caller-created token after an authenticated handoff."""
        if not token:
            raise ValidationError("credential cannot be empty")
        if not actor or "/" in actor or ".." in actor:
            raise ValidationError("invalid actor")
        path = self.root / f"{actor}.token"
        metadata = self.root / f"{actor}.json"
        if path.is_symlink() or metadata.is_symlink():
            raise ValidationError("credential path must not be a symlink")
        path.write_text(token, encoding="utf-8")
        path.chmod(0o600)
        metadata.write_text(json.dumps({"actor": actor, "scopes": sorted(set(scopes))}), encoding="utf-8")
        metadata.chmod(0o600)
        return path

    def load(self, token: str):
        if not token:
            raise AuthorizationError("bearer credential required")
        for token_path in self.root.glob("*.token"):
            try:
                expected = token_path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if secrets.compare_digest(expected, token):
                metadata_path = token_path.with_suffix(".json")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {"actor": token_path.stem, "scopes": []}
                return metadata
        raise AuthorizationError("invalid bearer credential")

    def require(self, token: str, scope: str):
        identity = self.load(token)
        if scope not in identity.get("scopes", []) and "admin" not in identity.get("scopes", []):
            raise AuthorizationError("credential lacks required scope", details={"scope": scope})
        return identity
