import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import HTTPException

from .config import settings
from .crypto import SENTINEL_PLAINTEXT, b64encode, decrypt_value, derive_key, encrypt_value, random_salt
from .schemas import ConfigFile, SecretListItem, StatusResponse


class SecretServiceError(HTTPException):
    pass


@dataclass
class UnlockState:
    key: bytes | None = None
    unlocked_until: datetime | None = None


class SecretService:
    def __init__(self) -> None:
        self.root: Path = settings.storage_root
        self.config_path = self.root / "config.json"
        self.sentinel_path = self.root / ".sentinel"
        self.index_path = self.root / "secret_index.db"
        self.legacy_index_path = self.root / "secret_index.json"
        self.state = UnlockState()

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def _secret_path(self, secret_id: str) -> Path:
        return self.root / f"{secret_id}.enc"

    def _connect_index(self) -> sqlite3.Connection:
        self._ensure_root()
        connection = sqlite3.connect(self.index_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_index(self) -> None:
        with self._connect_index() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS named_secrets (
                    secret_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    user_defined_type TEXT NOT NULL,
                    UNIQUE(name, user_defined_type)
                )
                """
            )
            connection.commit()
        self._migrate_legacy_index_if_needed()

    def _migrate_legacy_index_if_needed(self) -> None:
        if not self.legacy_index_path.exists():
            return
        legacy_index = json.loads(self.legacy_index_path.read_text() or "{}")
        with self._connect_index() as connection:
            existing = connection.execute("SELECT COUNT(*) FROM named_secrets").fetchone()[0]
            if existing == 0:
                for name, metadata in legacy_index.items():
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO named_secrets (secret_id, name, user_defined_type)
                        VALUES (?, ?, ?)
                        """,
                        (metadata["secret_id"], name, metadata["user_defined_type"]),
                    )
                connection.commit()
        self.legacy_index_path.unlink(missing_ok=True)

    def _load_config(self) -> ConfigFile:
        if not self.config_path.exists():
            raise SecretServiceError(status_code=404, detail="Secrets system is not initialized")
        return ConfigFile.model_validate_json(self.config_path.read_text())

    def _save_config(self, config: ConfigFile) -> None:
        self._ensure_root()
        self.config_path.write_text(json.dumps(config.model_dump(), indent=2))

    def _get_named_secret_by_name_and_type(self, name: str, user_defined_type: str) -> sqlite3.Row | None:
        self._ensure_index()
        with self._connect_index() as connection:
            return connection.execute(
                """
                SELECT secret_id, name, user_defined_type
                FROM named_secrets
                WHERE name = ? AND user_defined_type = ?
                """,
                (name, user_defined_type),
            ).fetchone()

    def _get_named_secret_by_id(self, secret_id: str) -> sqlite3.Row | None:
        self._ensure_index()
        with self._connect_index() as connection:
            return connection.execute(
                """
                SELECT secret_id, name, user_defined_type
                FROM named_secrets
                WHERE secret_id = ?
                """,
                (secret_id,),
            ).fetchone()

    def _list_named_secret_rows(self) -> list[sqlite3.Row]:
        self._ensure_index()
        with self._connect_index() as connection:
            return connection.execute(
                """
                SELECT secret_id, name, user_defined_type
                FROM named_secrets
                ORDER BY user_defined_type, name
                """
            ).fetchall()

    def _list_names_for_type(self, user_defined_type: str) -> list[str]:
        self._ensure_index()
        with self._connect_index() as connection:
            rows = connection.execute(
                """
                SELECT name
                FROM named_secrets
                WHERE user_defined_type = ?
                ORDER BY name
                """,
                (user_defined_type,),
            ).fetchall()
        return [row["name"] for row in rows]

    def _insert_named_secret(self, secret_id: str, name: str, user_defined_type: str) -> None:
        self._ensure_index()
        with self._connect_index() as connection:
            connection.execute(
                """
                INSERT INTO named_secrets (secret_id, name, user_defined_type)
                VALUES (?, ?, ?)
                """,
                (secret_id, name, user_defined_type),
            )
            connection.commit()

    def _delete_named_secret_row(self, secret_id: str) -> None:
        self._ensure_index()
        with self._connect_index() as connection:
            connection.execute("DELETE FROM named_secrets WHERE secret_id = ?", (secret_id,))
            connection.commit()

    def _encode_secret_value(self, value: object) -> bytes:
        return json.dumps(value).encode("utf-8")

    def _decode_secret_value(self, payload: bytes) -> object:
        return json.loads(payload.decode("utf-8"))

    def _is_unlocked(self) -> bool:
        if self.state.key is None or self.state.unlocked_until is None:
            return False
        return datetime.now(UTC) < self.state.unlocked_until

    def _require_unlocked(self) -> bytes:
        if not self._is_unlocked():
            self.state = UnlockState()
            raise SecretServiceError(status_code=423, detail="Secrets system is locked")
        assert self.state.key is not None
        return self.state.key

    def _derive_and_validate(self, passphrase: str) -> tuple[ConfigFile, bytes]:
        config = self._load_config()
        key = derive_key(passphrase, config)
        if not self.sentinel_path.exists():
            raise SecretServiceError(status_code=500, detail="Sentinel file is missing")
        try:
            plaintext = decrypt_value(key, self.sentinel_path.read_bytes())
        except Exception as exc:  # noqa: BLE001
            raise SecretServiceError(status_code=401, detail="Invalid passphrase") from exc
        if plaintext != SENTINEL_PLAINTEXT:
            raise SecretServiceError(status_code=401, detail="Invalid passphrase")
        return config, key

    def status(self) -> StatusResponse:
        initialized = self.config_path.exists() and self.sentinel_path.exists()
        default_ttl = None
        if initialized:
            default_ttl = self._load_config().default_unlock_ttl_seconds
        return StatusResponse(
            initialized=initialized,
            locked=not self._is_unlocked(),
            unlocked_until=self.state.unlocked_until.isoformat() if self._is_unlocked() else None,
            default_unlock_ttl_seconds=default_ttl,
        )

    def init(self, passphrase: str, unlock_ttl_seconds: int) -> StatusResponse:
        if self.config_path.exists() or self.sentinel_path.exists():
            raise SecretServiceError(status_code=409, detail="Secrets system is already initialized")
        self._ensure_root()
        self._ensure_index()
        config = ConfigFile(
            salt_b64=b64encode(random_salt()),
            default_unlock_ttl_seconds=unlock_ttl_seconds,
        )
        key = derive_key(passphrase, config)
        self._save_config(config)
        self.sentinel_path.write_bytes(encrypt_value(key, SENTINEL_PLAINTEXT))
        self.state = UnlockState(
            key=key,
            unlocked_until=datetime.now(UTC) + timedelta(seconds=unlock_ttl_seconds),
        )
        return self.status()

    def unlock(self, passphrase: str, unlock_ttl_seconds: int) -> StatusResponse:
        _config, key = self._derive_and_validate(passphrase)
        self.state = UnlockState(
            key=key,
            unlocked_until=datetime.now(UTC) + timedelta(seconds=unlock_ttl_seconds),
        )
        return self.status()

    def lock(self) -> StatusResponse:
        self.state = UnlockState()
        return self.status()

    def update_ttl(self, passphrase: str, unlock_ttl_seconds: int) -> StatusResponse:
        config, _key = self._derive_and_validate(passphrase)
        config.default_unlock_ttl_seconds = unlock_ttl_seconds
        self._save_config(config)
        return self.status()

    def create_secret(self, name: str, user_defined_type: str, passphrase: str, value: object) -> dict[str, str]:
        _config, key = self._derive_and_validate(passphrase)
        existing = self._get_named_secret_by_name_and_type(name, user_defined_type)
        if existing is not None:
            raise SecretServiceError(status_code=409, detail="Secret name and type already exist")
        secret_id = str(uuid.uuid4())
        self._secret_path(secret_id).write_bytes(encrypt_value(key, self._encode_secret_value(value)))
        self._insert_named_secret(secret_id, name, user_defined_type)
        return {
            "name": name,
            "user_defined_type": user_defined_type,
            "secret_id": secret_id,
        }

    def list_secrets(self) -> list[SecretListItem]:
        if not self.config_path.exists() or not self.sentinel_path.exists():
            return []
        key = self._require_unlocked()
        secrets: list[SecretListItem] = []
        for row in self._list_named_secret_rows():
            path = self._secret_path(row["secret_id"])
            try:
                value = self._decode_secret_value(decrypt_value(key, path.read_bytes()))
            except Exception as exc:  # noqa: BLE001
                self.state = UnlockState()
                raise SecretServiceError(status_code=423, detail="Secrets system is locked") from exc
            secrets.append(
                SecretListItem(
                    name=row["name"],
                    user_defined_type=row["user_defined_type"],
                    secret_id=row["secret_id"],
                    value=value,
                )
            )
        return secrets

    def read_secret(self, secret_id: str) -> dict[str, object]:
        key = self._require_unlocked()
        row = self._get_named_secret_by_id(secret_id)
        if row is None:
            raise SecretServiceError(status_code=404, detail="Secret not found")
        path = self._secret_path(secret_id)
        if not path.exists():
            raise SecretServiceError(status_code=404, detail="Secret not found")
        try:
            value = self._decode_secret_value(decrypt_value(key, path.read_bytes()))
        except Exception as exc:  # noqa: BLE001
            self.state = UnlockState()
            raise SecretServiceError(status_code=423, detail="Secrets system is locked") from exc
        return {
            "name": row["name"],
            "user_defined_type": row["user_defined_type"],
            "secret_id": secret_id,
            "value": value,
        }

    def replace_secret(self, secret_id: str, passphrase: str, value: object) -> None:
        _config, key = self._derive_and_validate(passphrase)
        if self._get_named_secret_by_id(secret_id) is None:
            raise SecretServiceError(status_code=404, detail="Secret not found")
        path = self._secret_path(secret_id)
        if not path.exists():
            raise SecretServiceError(status_code=404, detail="Secret not found")
        path.write_bytes(encrypt_value(key, self._encode_secret_value(value)))

    def delete_secret(self, secret_id: str, passphrase: str) -> None:
        self._derive_and_validate(passphrase)
        if self._get_named_secret_by_id(secret_id) is None:
            raise SecretServiceError(status_code=404, detail="Secret not found")
        path = self._secret_path(secret_id)
        if not path.exists():
            raise SecretServiceError(status_code=404, detail="Secret not found")
        path.unlink()
        self._delete_named_secret_row(secret_id)

    def upsert_named_secret(self, name: str, user_defined_type: str, passphrase: str, value: object) -> dict[str, str]:
        _config, key = self._derive_and_validate(passphrase)
        existing = self._get_named_secret_by_name_and_type(name, user_defined_type)
        if existing is None:
            secret_id = str(uuid.uuid4())
            self._insert_named_secret(secret_id, name, user_defined_type)
        else:
            secret_id = existing["secret_id"]
        self._secret_path(secret_id).write_bytes(encrypt_value(key, self._encode_secret_value(value)))
        return {
            "name": name,
            "user_defined_type": user_defined_type,
            "secret_id": secret_id,
        }

    def delete_named_secret(self, name: str, user_defined_type: str, passphrase: str) -> None:
        self._derive_and_validate(passphrase)
        existing = self._get_named_secret_by_name_and_type(name, user_defined_type)
        if existing is None:
            raise SecretServiceError(status_code=404, detail="Named secret not found")
        path = self._secret_path(existing["secret_id"])
        if not path.exists():
            raise SecretServiceError(status_code=404, detail="Named secret not found")
        path.unlink()
        self._delete_named_secret_row(existing["secret_id"])

    def get_names_of_secrets_by_type(self, user_defined_type: str) -> list[str]:
        if not self.config_path.exists() or not self.sentinel_path.exists():
            return []
        return self._list_names_for_type(user_defined_type)

    def testing_reset(self) -> StatusResponse:
        # Testing-only escape hatch. Remove before shipping.
        self.state = UnlockState()
        if self.root.exists():
            for path in self.root.glob("*.enc"):
                path.unlink(missing_ok=True)
            self.config_path.unlink(missing_ok=True)
            self.sentinel_path.unlink(missing_ok=True)
            self.index_path.unlink(missing_ok=True)
            self.legacy_index_path.unlink(missing_ok=True)
        return self.status()


secret_service = SecretService()
