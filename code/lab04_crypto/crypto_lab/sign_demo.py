from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MESSAGE = b"lab4 demo message"


def make_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def is_valid(key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def compare_schemes() -> list[tuple[str, int, int, bool]]:
    ed = Ed25519PrivateKey.generate()
    ecdsa = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
    )
    sign = {
        "Ed25519": lambda: ed.sign(MESSAGE),
        "ECDSA P-256": lambda: ecdsa.sign(MESSAGE, ec.ECDSA(hashes.SHA256())),
        "RSA-PSS 2048": lambda: rsa_key.sign(MESSAGE, pss, hashes.SHA256()),
    }
    ec_public = ecdsa.public_key()
    point = ec_public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    public = {
        "Ed25519": len(raw_public(ed.public_key())),
        "ECDSA P-256": len(point),
        "RSA-PSS 2048": rsa_key.key_size // 8,
    }
    rows = []
    for name, make in sign.items():
        first = make()
        rows.append((name, public[name], len(first), first == make()))
    return rows


def main() -> None:
    private_key, public_key = make_keys()
    signature = private_key.sign(MESSAGE)
    print("відкритий ключ:", raw_public(public_key).hex())
    print("підпис:", signature.hex())
    print("правильне повідомлення:", is_valid(public_key, signature, MESSAGE))
    print("повідомлення + b'x':", is_valid(public_key, signature, MESSAGE + b"x"))
    broken = bytes([signature[0] ^ 1]) + signature[1:]
    print("змінений байт підпису:", is_valid(public_key, broken, MESSAGE))
    other = make_keys()[1]
    print("чужий відкритий ключ:", is_valid(other, signature, MESSAGE))


if __name__ == "__main__":
    main()
