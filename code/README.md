# ЛР4. Дослідження та реалізація криптографічних механізмів

Дисципліна "Безпека програмного забезпечення", КПІ ім. Ігоря Сікорського.
Віжуткін Ілля, група ІП-31, варіант 4.

Варіант 4: AEAD ChaCha20-Poly1305, підпис Ed25519, RSA з множниками по 20 біт,
типові помилки "режим ECB замість AEAD" і "хешування пароля без солі".

Каркас (crypto_lab/rsa_edu.py, tests/test_rsa.py) і common/variants.py взято з
репозиторію курсу. Власний код:

- lab04_crypto/crypto_lab/aead.py - шифрування і розшифрування ChaCha20-Poly1305
- lab04_crypto/crypto_lab/misuse.py - дві помилки варіанта і безпечні заміни
- lab04_crypto/crypto_lab/sign_demo.py - підпис Ed25519 і порівняння схем підпису
- lab04_crypto/demo.py - демонстрація всіх частин і вимірювання
- lab04_crypto/tests/test_variant.py - власні тести
- structure.drawio, structure.png - структурна схема

Усі ключі, паролі і дані в коді тестові.

Запуск (з каталогу code):

    python -m common.variants 4 --lab 4
    cd lab04_crypto
    pip install -r requirements.txt
    python demo.py
    python -m crypto_lab.sign_demo
    python -m pytest tests/
