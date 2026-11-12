import hashlib
import re
import secrets

ITERATIONS = 600000


def hash_password(password):
    """Securely hash a password using PBKDF2."""

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )

    return salt.hex() + ":" + password_hash.hex()


def verify_password(password, stored_hash):
    """Verify a password against its stored hash."""

    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)

        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            ITERATIONS
        )

        return secrets.compare_digest(
            new_hash.hex(),
            hash_hex
        )

    except (ValueError, TypeError, AttributeError):
        return False


def validate_username(username):
    """Validate username input."""

    return bool(
        re.fullmatch(r'[A-Za-z0-9_]{3,20}', username)
    )


def validate_password(password):
    """Check password strength and length limits."""

    # Upper limit stops very long inputs from tying up the CPU (DoS).
    if len(password) < 8 or len(password) > 128:
        return False

    if not re.search(r'[A-Z]', password):
        return False

    if not re.search(r'[a-z]', password):
        return False

    if not re.search(r'[0-9]', password):
        return False

    if not re.search(r'[^A-Za-z0-9]', password):
        return False

    return True