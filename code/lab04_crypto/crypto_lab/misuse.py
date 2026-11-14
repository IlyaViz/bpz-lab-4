import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto_lab import aead

BLOCK_BYTES = 16
SALT_BYTES = 16


def blocks(data: bytes) -> list[bytes]:
    return [data[i : i + BLOCK_BYTES] for i in range(0, len(data), BLOCK_BYTES)]


def repeated_blocks(data: bytes) -> int:
    parts = blocks(data)
    return len(parts) - len(set(parts))


# ВРАЗЛИВО: режим ECB шифрує кожен 16-байтовий блок окремо і без тегу
def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_BYTES * 8).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


# БЕЗПЕЧНО: AEAD варіанта (ChaCha20-Poly1305) з новим nonce і тегом
def aead_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return aead.encrypt(plaintext, key)


# ВРАЗЛИВО: шифрування без контролю цілісності, шифротекст можна змінити
def stream_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    encryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def stream_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    decryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ВРАЗЛИВО: хеш пароля без солі, однакові паролі дають однакові хеші
def hash_unsalted(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def crack_with_table(stored: str, dictionary: list[str]) -> str | None:
    table = {hash_unsalted(word): word for word in dictionary}
    return table.get(stored)


def slow_hash(password: str, salt: bytes) -> bytes:
    data = password.encode()
    return hashlib.scrypt(data, salt=salt, n=2**14, r=8, p=1, dklen=32)


# БЕЗПЕЧНО: випадкова сіль на кожен запис і повільна функція scrypt
def hash_salted(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    return f"{salt.hex()}${slow_hash(password, salt).hex()}"


def verify_salted(stored: str, password: str) -> bool:
    salt_hex, key_hex = stored.split("$")
    key = slow_hash(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(key, bytes.fromhex(key_hex))
