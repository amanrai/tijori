import base64
import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .schemas import ConfigFile


SENTINEL_PLAINTEXT = b"scryer-secrets-sentinel-v1"


def random_salt() -> bytes:
    return os.urandom(16)


def random_nonce() -> bytes:
    return os.urandom(12)


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(passphrase: str, config: ConfigFile) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=b64decode(config.salt_b64),
        time_cost=config.argon2_time_cost,
        memory_cost=config.argon2_memory_cost_kib,
        parallelism=config.argon2_parallelism,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_value(key: bytes, plaintext: bytes) -> bytes:
    nonce = random_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    payload = {
        "version": 1,
        "nonce_b64": b64encode(nonce),
        "ciphertext_b64": b64encode(ciphertext),
    }
    return json.dumps(payload).encode("utf-8")


def decrypt_value(key: bytes, payload: bytes) -> bytes:
    data = json.loads(payload.decode("utf-8"))
    nonce = b64decode(data["nonce_b64"])
    ciphertext = b64decode(data["ciphertext_b64"])
    return AESGCM(key).decrypt(nonce, ciphertext, None)
