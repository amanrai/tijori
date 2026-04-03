from typing import Any

from pydantic import BaseModel, Field, field_validator

from .config import MAX_UNLOCK_TTL_SECONDS


class InitRequest(BaseModel):
    passphrase: str = Field(min_length=1)
    unlock_ttl_seconds: int = Field(gt=0, le=MAX_UNLOCK_TTL_SECONDS)


class UnlockRequest(BaseModel):
    passphrase: str = Field(min_length=1)
    unlock_ttl_seconds: int = Field(gt=0, le=MAX_UNLOCK_TTL_SECONDS)


class LockResponse(BaseModel):
    locked: bool


class TTLRequest(BaseModel):
    passphrase: str = Field(min_length=1)
    unlock_ttl_seconds: int = Field(gt=0, le=MAX_UNLOCK_TTL_SECONDS)


class SecretCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    user_defined_type: str = Field(min_length=1)
    passphrase: str = Field(min_length=1)
    value: Any


class SecretUpdateRequest(BaseModel):
    passphrase: str = Field(min_length=1)
    value: Any


class SecretDeleteRequest(BaseModel):
    passphrase: str = Field(min_length=1)


class SecretResponse(BaseModel):
    name: str
    user_defined_type: str
    secret_id: str
    value: Any


class SecretCreateResponse(BaseModel):
    name: str
    user_defined_type: str
    secret_id: str


class SecretListItem(BaseModel):
    name: str
    user_defined_type: str
    secret_id: str
    value: Any


class NamedSecretUpsertRequest(BaseModel):
    name: str = Field(min_length=1)
    user_defined_type: str = Field(min_length=1)
    passphrase: str = Field(min_length=1)
    value: Any


class NamedSecretDeleteRequest(BaseModel):
    name: str = Field(min_length=1)
    user_defined_type: str = Field(min_length=1)
    passphrase: str = Field(min_length=1)


class NamesOfSecretsByTypeRequest(BaseModel):
    user_defined_type: str = Field(min_length=1)


class NamesOfSecretsByTypeResponse(BaseModel):
    names: list[str]


class SecretListResponse(BaseModel):
    secrets: list[SecretListItem]


class StatusResponse(BaseModel):
    initialized: bool
    locked: bool
    unlocked_until: str | None
    default_unlock_ttl_seconds: int | None


class InitResponse(BaseModel):
    initialized: bool
    locked: bool
    unlocked_until: str | None


class ConfigFile(BaseModel):
    version: int = 1
    salt_b64: str
    default_unlock_ttl_seconds: int = Field(gt=0, le=MAX_UNLOCK_TTL_SECONDS)
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65_536, ge=8_192)
    argon2_parallelism: int = Field(default=4, ge=1)

    @field_validator("salt_b64")
    @classmethod
    def validate_salt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("salt must not be empty")
        return value
