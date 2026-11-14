import os
import sys

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto_lab import aead, misuse, sign_demo
from crypto_lab.rsa_edu import decrypt, encrypt, fast_pow_mod, keygen

KEY = b"0" * 32
TEXT = b"ATTACK AT DAWN!!" * 4


def flip(data: bytes, position: int) -> bytes:
    return data[:position] + bytes([data[position] ^ 1]) + data[position + 1 :]


def test_aead_roundtrip_with_associated_data():
    blob = aead.encrypt(b"secret", KEY, associated=b"hdr")
    assert aead.decrypt(blob, KEY, associated=b"hdr") == b"secret"


def test_aead_blob_layout():
    blob = aead.encrypt(b"secret", KEY)
    assert len(blob) == aead.NONCE_BYTES + len(b"secret") + 16


def test_aead_new_nonce_every_time():
    nonces = {aead.encrypt(b"secret", KEY)[: aead.NONCE_BYTES] for _ in range(50)}
    assert len(nonces) == 50


@pytest.mark.parametrize("position", [0, 12, -1])
def test_aead_rejects_changed_bit(position):
    blob = aead.encrypt(b"secret payload", KEY, associated=b"hdr")
    with pytest.raises(InvalidTag):
        aead.decrypt(flip(blob, position % len(blob)), KEY, associated=b"hdr")


def test_aead_rejects_other_associated_data():
    blob = aead.encrypt(b"secret", KEY, associated=b"hdr")
    with pytest.raises(InvalidTag):
        aead.decrypt(blob, KEY, associated=b"hdx")


def test_aead_rejects_other_key():
    blob = aead.encrypt(b"secret", KEY)
    with pytest.raises(InvalidTag):
        aead.decrypt(blob, b"1" * 32)


def test_ecb_shows_repeated_blocks():
    assert misuse.repeated_blocks(misuse.ecb_encrypt(TEXT, KEY)) == 3


def test_aead_hides_repeated_blocks():
    assert misuse.repeated_blocks(misuse.aead_encrypt(TEXT, KEY)) == 0


def test_stream_without_tag_can_be_changed():
    nonce = bytes(16)
    data = bytearray(misuse.stream_encrypt(b"amount=100", KEY, nonce))
    data[7] ^= ord("1") ^ ord("9")
    assert misuse.stream_decrypt(bytes(data), KEY, nonce) == b"amount=900"


def test_unsalted_hashes_repeat_and_crack():
    first = misuse.hash_unsalted("qwerty123")
    assert first == misuse.hash_unsalted("qwerty123")
    assert misuse.crack_with_table(first, ["admin", "qwerty123"]) == "qwerty123"


def test_salted_hashes_differ_and_verify():
    first = misuse.hash_salted("qwerty123")
    second = misuse.hash_salted("qwerty123")
    assert first != second
    assert misuse.verify_salted(first, "qwerty123")
    assert not misuse.verify_salted(first, "qwerty124")


def test_salted_hash_not_in_table():
    key = misuse.hash_salted("qwerty123").split("$")[1]
    assert misuse.crack_with_table(key, ["qwerty123"]) is None


def test_ed25519_sign_and_verify():
    private_key, public_key = sign_demo.make_keys()
    signature = private_key.sign(b"msg")
    assert len(signature) == 64 and len(sign_demo.raw_public(public_key)) == 32
    assert sign_demo.is_valid(public_key, signature, b"msg")
    assert private_key.sign(b"msg") == signature


def test_ed25519_rejects_changes():
    private_key, public_key = sign_demo.make_keys()
    signature = private_key.sign(b"msg")
    assert not sign_demo.is_valid(public_key, signature, b"msh")
    assert not sign_demo.is_valid(public_key, flip(signature, 0), b"msg")
    other = sign_demo.make_keys()[1]
    assert not sign_demo.is_valid(other, signature, b"msg")


def test_variant_rsa_key():
    key = keygen(bits=20)
    assert key["p"].bit_length() == 20 and key["q"].bit_length() == 20
    assert key["e"] * key["d"] % key["phi"] == 1
    assert decrypt(encrypt(42, key["e"], key["n"]), key["d"], key["n"]) == 42


def test_fast_pow_steps_follow_bit_length():
    _, steps = fast_pow_mod(42, 65537, 703696947361)
    assert len(steps) == (65537).bit_length() == 17
