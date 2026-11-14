import time

from cryptography.exceptions import InvalidTag

from crypto_lab import aead, misuse, sign_demo
from crypto_lab.rsa_edu import (
    decrypt,
    egcd,
    encrypt,
    fast_pow_mod,
    gen_prime,
    is_probable_prime,
    keygen,
    modinv,
)

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
KEY = b"0" * 32
# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
SAVED_RSA = {
    "p": 687437,
    "q": 1023653,
    "n": 703696947361,
    "phi": 703695236272,
    "e": 65537,
    "d": 379920480721,
}
BITS = 20
PICTURE = [
    b"################",
    b"#              #",
    b"#   ##    ##   #",
    b"#              #",
    b"#  #        #  #",
    b"#   ########   #",
    b"#              #",
    b"################",
]
PASSWORDS = {"olena": "qwerty123", "taras": "qwerty123", "ivan": "Sunflower!7"}
DICTIONARY = ["123456", "password", "qwerty123", "iloveyou", "admin"]


def rsa_parts() -> None:
    print("1. Перевірка складників RSA")
    value, steps = fast_pow_mod(7, 13, 100)
    print("fast_pow_mod(7, 13, 100) =", value)
    for step in steps:
        print("   ", step)
    print("is_probable_prime(7919):", is_probable_prime(7919))
    print("is_probable_prime(7917):", is_probable_prime(7917))
    print("egcd(240, 46):", egcd(240, 46))
    print("modinv(17, 3120):", modinv(17, 3120))
    p, q, e = 61, 53, 17
    n, phi = p * q, (p - 1) * (q - 1)
    d = modinv(e, phi)
    c = encrypt(65, e, n)
    print(f"p = {p}, q = {q}, e = {e}: n = {n}, phi = {phi}, d = {d}")
    print(f"m = 65 -> c = {c} -> m = {decrypt(c, d, n)}")


def rsa_keys() -> None:
    print(f"\n2. Ключі RSA, множники по {BITS} біт")
    k = SAVED_RSA
    for name in ("p", "q", "n", "phi", "e", "d"):
        print(f"    {name} = {k[name]}")
    primes = is_probable_prime(k["p"]) and is_probable_prime(k["q"])
    print("p і q прості:", primes)
    sizes = [k[name].bit_length() for name in ("p", "q", "n")]
    print("розрядність p, q, n:", sizes)
    print("n = p * q:", k["n"] == k["p"] * k["q"])
    print("phi = (p - 1) * (q - 1):", k["phi"] == (k["p"] - 1) * (k["q"] - 1))
    print("e * d mod phi =", k["e"] * k["d"] % k["phi"])
    c = encrypt(42, k["e"], k["n"])
    print(f"m = 42 -> c = {c} -> m = {decrypt(c, k['d'], k['n'])}")
    fresh = keygen(bits=BITS)
    m = decrypt(encrypt(42, fresh["e"], fresh["n"]), fresh["d"], fresh["n"])
    ok = (
        fresh["p"].bit_length() == BITS
        and is_probable_prime(fresh["p"])
        and is_probable_prime(fresh["q"])
        and fresh["e"] * fresh["d"] % fresh["phi"] == 1
        and m == 42
    )
    print(f"нова пара keygen(bits={BITS}), n = {fresh['n']}, перевірки: {ok}")


def verdict(blob: bytes, key: bytes = KEY, associated: bytes = b"hdr") -> str:
    try:
        aead.decrypt(blob, key, associated)
    except InvalidTag:
        return "OK, тег відхилив підміну"
    return "ПОМИЛКА: підміну не виявлено"


def flip(data: bytes, position: int, mask: int) -> bytes:
    return data[:position] + bytes([data[position] ^ mask]) + data[position + 1 :]


def authenticated() -> None:
    print("\n3. AEAD ChaCha20-Poly1305")
    blob = aead.encrypt(b"secret payload", KEY, associated=b"hdr")
    print("довжина blob: nonce 12 + текст 14 + тег 16 =", len(blob))
    print("розшифровано:", aead.decrypt(blob, KEY, associated=b"hdr"))
    again = aead.encrypt(b"secret payload", KEY, associated=b"hdr")
    print("те саме повідомлення вдруге дає інший nonce:", again[:12] != blob[:12])
    body = flip(blob, 12, 1)
    tag = flip(blob, len(blob) - 1, 1)
    print("змінено 1 біт шифротексту:", verdict(body))
    print("змінено 1 біт тегу:", verdict(tag))
    print("змінено асоційовані дані:", verdict(blob, associated=b"hdx"))
    print("інший ключ:", verdict(blob, key=b"1" * 32))
    nonce = bytes(16)
    mask = ord("1") ^ ord("9")
    stream = misuse.stream_encrypt(b"amount=100", KEY, nonce)
    forged = misuse.stream_decrypt(flip(stream, 7, mask), KEY, nonce)
    print("без тегу: amount=100 після зміни 1 біта шифротексту ->", forged)
    sealed = flip(aead.encrypt(b"amount=100", KEY), 12 + 7, mask)
    print("з тегом та сама зміна:", verdict(sealed, associated=b""))


def names(parts: list[bytes]) -> list[str]:
    seen: dict[bytes, str] = {}
    for part in parts:
        seen.setdefault(part, "ABCDEFGHIJKLMNOP"[len(seen)])
    return [seen[part] for part in parts]


def ecb_mistake() -> None:
    print("\n4. Помилка 1: режим ECB замість AEAD")
    data = b"".join(PICTURE)
    ecb = misuse.ecb_encrypt(data, KEY)[: len(data)]
    safe = misuse.aead_encrypt(data, KEY)[12 : 12 + len(data)]
    print("блоків по 16 байтів:", len(PICTURE))
    print("однакових блоків у відкритому тексті:", misuse.repeated_blocks(data))
    print("однакових блоків у шифротексті ECB:", misuse.repeated_blocks(ecb))
    print("однакових блоків у шифротексті AEAD:", misuse.repeated_blocks(safe))
    print("рядок картинки      ECB  AEAD")
    rows = zip(PICTURE, names(misuse.blocks(ecb)), names(misuse.blocks(safe)))
    for row, ecb_name, safe_name in rows:
        print(f"    {row.decode()}  {ecb_name}    {safe_name}")


def average(action, runs: int) -> float:
    start = time.perf_counter()
    for _ in range(runs):
        action()
    return (time.perf_counter() - start) / runs


def salt_mistake() -> None:
    print("\n5. Помилка 2: хешування пароля без солі")
    plain = {user: misuse.hash_unsalted(pw) for user, pw in PASSWORDS.items()}
    for user, digest in plain.items():
        print(f"    {user:<6} SHA-256 {digest[:24]}...")
    print("olena і taras мають однаковий хеш:", plain["olena"] == plain["taras"])
    for user, digest in plain.items():
        found = misuse.crack_with_table(digest, DICTIONARY)
        print(f"    таблиця словника, {user}: {found}")
    salted = {user: misuse.hash_salted(pw) for user, pw in PASSWORDS.items()}
    same = salted["olena"] == salted["taras"]
    print("olena і taras мають однаковий запис із сіллю:", same)
    keys = [record.split("$")[1] for record in salted.values()]
    found = [misuse.crack_with_table(key, DICTIONARY) for key in keys]
    print("таблиця словника для записів із сіллю:", found)
    ok = misuse.verify_salted(salted["olena"], "qwerty123")
    print("пароль olena із сіллю перевіряється:", ok)
    fast = average(lambda: misuse.hash_unsalted("qwerty123"), 1000) * 1e6
    slow = average(lambda: misuse.hash_salted("qwerty123"), 10) * 1e3
    print(f"час одного хешу: SHA-256 {fast:.2f} мкс, scrypt {slow:.1f} мс")


def signature() -> None:
    print("\n6. Електронний підпис Ed25519")
    sign_demo.main()
    print("    схема         ключ  підпис  однаковий при повторі")
    for name, public, size, same in sign_demo.compare_schemes():
        print(f"    {name:<13} {public:>4} {size:>6}  {same}")


def factor(n: int) -> tuple[int, int]:
    divisor, tries = 3, 1
    while n % divisor:
        divisor += 2
        tries += 1
    return divisor, tries


def prime_below(limit: int) -> int:
    candidate = limit - 1 if limit % 2 == 0 else limit - 2
    while not is_probable_prime(candidate):
        candidate -= 2
    return candidate


def readable(seconds: float) -> str:
    if seconds < 3600:
        return f"{seconds / 60:.1f} хв"
    if seconds < 24 * 3600:
        return f"{seconds / 3600:.1f} год"
    if seconds < 365 * 24 * 3600:
        return f"{seconds / (24 * 3600):.1f} діб"
    return f"{seconds / (365 * 24 * 3600):.3g} років"


def growth() -> None:
    print("\n7. Залежність від розрядності")
    print("    біт  генерація простого, мс (середнє з 20)")
    for bits in (20, 64, 128, 256, 512):
        spent = average(lambda: gen_prime(bits), 20) * 1e3
        print(f"    {bits:3} {spent:10.2f}")
    print("    біт  ділень перебором   факторизація n, мс")
    for bits in (12, 16, 20, 24):
        p = prime_below(2**bits)
        q = prime_below(p)
        start = time.perf_counter()
        found, tries = factor(p * q)
        spent = (time.perf_counter() - start) * 1e3
        print(f"    {bits:3} {tries:14} {spent:14.2f}  (знайдено {found})")
    per_try = spent / 1e3 / tries
    print(f"    одне ділення: {per_try * 1e9:.0f} нс, оцінка перебору:")
    for bits in (32, 40, 48, 64):
        print(f"    {bits:3} біт: {readable(2 ** (bits - 1) * per_try)}")
    print("    показник       біт  кроків  множень  наївно множень")
    for name in ("e", "d"):
        exp = SAVED_RSA[name]
        _, steps = fast_pow_mod(42, exp, SAVED_RSA["n"])
        total = len(steps) + bin(exp).count("1")
        row = f"{name} = {exp:<13} {exp.bit_length():2} {len(steps):6} {total:7}"
        print(f"    {row}  {exp - 1}")


if __name__ == "__main__":
    rsa_parts()
    rsa_keys()
    authenticated()
    ecb_mistake()
    salt_mistake()
    signature()
    growth()
