"""
backend/storage_engine/crypto.py

Field-level encryption for sensitive data before it's written to
SQLite. Uses Fernet (from the `cryptography` library) -- this is
AES-128 in CBC mode with HMAC authentication under the hood, a real,
audited encryption scheme, not custom/homemade crypto.

WHY FIELD-LEVEL instead of full-database encryption (SQLCipher):
SQLCipher requires swapping Python's built-in sqlite3 module for a
special build (pysqlcipher3), which needs OS-level compiled
dependencies that can be fragile to install cross-platform under
time pressure. Field-level encryption uses pure-Python `cryptography`
(no special build), works identically on any machine, and lets you
encrypt exactly the sensitive columns (raw email content, headers)
while leaving structural/risk-score data queryable for your app.
This is a legitimate, real security control -- not a placeholder --
and SQLCipher remains a valid future upgrade once you have time to
test it properly.

Setup (one-time):
    pip3 install cryptography

    Generate a real encryption key and add it to your .env:
        python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

    Add to .env:
        DB_ENCRYPTION_KEY=<the key printed above>

CRITICAL: if you lose this key, every encrypted field becomes
permanently unreadable -- there is no recovery. Back it up somewhere
safe, separate from the database file itself (never commit it to git).
"""

import os
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()  # ensures DB_ENCRYPTION_KEY is available even when this
                # module is imported by a script that doesn't call
                # load_dotenv() itself (e.g. integrate.py run standalone)

_key = os.environ.get("DB_ENCRYPTION_KEY")
_fernet = Fernet(_key.encode()) if _key else None


def is_encryption_configured():
    return _fernet is not None


def encrypt_field(plaintext):
    """
    Encrypts a string for storage. Returns None if encryption isn't
    configured (DB_ENCRYPTION_KEY missing) OR if plaintext is empty --
    callers should check is_encryption_configured() at startup if
    encryption is required, rather than silently storing plaintext.
    """
    if plaintext is None:
        return None
    if not _fernet:
        raise RuntimeError(
            "DB_ENCRYPTION_KEY is not set in .env -- cannot encrypt. "
            "Generate one with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return _fernet.encrypt(str(plaintext).encode("utf-8")).decode("utf-8")


def decrypt_field(ciphertext):
    """
    Decrypts a value previously written by encrypt_field(). Returns
    None if ciphertext is None. Raises InvalidToken if the key is
    wrong or the data was tampered with -- this is Fernet's built-in
    authentication check, not something we added.
    """
    if ciphertext is None:
        return None
    if not _fernet:
        raise RuntimeError("DB_ENCRYPTION_KEY is not set in .env -- cannot decrypt.")
    return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


if __name__ == "__main__":
    # Quick self-test + key generator
    if not _key:
        print("[!] DB_ENCRYPTION_KEY not set. Generating one for you:\n")
        print(f"DB_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
        print("\nAdd that exact line to your .env file, then re-run this script to self-test.")
    else:
        sample = "This is a test of the encryption round-trip."
        encrypted = encrypt_field(sample)
        decrypted = decrypt_field(encrypted)
        print(f"Original:  {sample}")
        print(f"Encrypted: {encrypted[:50]}...")
        print(f"Decrypted: {decrypted}")
        print(f"\nRound-trip successful: {sample == decrypted}")