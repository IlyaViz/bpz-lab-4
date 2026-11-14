"""Симетричне шифрування — КАРКАС для лабораторної роботи 4.

Здобувач реалізує шифрування за AEAD свого варіанта і демонструє наслідки
двох типових помилок зі свого завдання (ECB, повторний nonce тощо).
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_BYTES = 12


# БЕЗПЕЧНО: новий nonce на кожне повідомлення, тег покриває асоційовані дані
def encrypt(plaintext: bytes, key: bytes, associated: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated)


def decrypt(blob: bytes, key: bytes, associated: bytes = b"") -> bytes:
    nonce, body = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return ChaCha20Poly1305(key).decrypt(nonce, body, associated)
