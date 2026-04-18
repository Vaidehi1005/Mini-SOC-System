from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


def _normalize_key(key: bytes | str) -> bytes:
    if isinstance(key, str):
        return key.strip().encode("utf-8")
    return key


def generate_key() -> bytes:
    return Fernet.generate_key()


def encrypt_file(data: bytes, key: bytes | str) -> bytes:
    cipher = Fernet(_normalize_key(key))
    return cipher.encrypt(data)


def encrypt_with_generated_key(data: bytes) -> tuple[bytes, bytes]:
    key = generate_key()
    return encrypt_file(data, key), key


def decrypt_file(data: bytes, user_key: bytes | str) -> bytes:
    try:
        cipher = Fernet(_normalize_key(user_key))
        return cipher.decrypt(data)
    except (ValueError, InvalidToken) as error:
        raise ValueError("Invalid key or corrupted encrypted file.") from error
