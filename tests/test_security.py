import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from security import (
    hash_password,
    verify_password,
    validate_username,
    validate_password,
)


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Use a temporary database so tests never touch the real users.db."""
    monkeypatch.setattr(database, "DATABASE_NAME", str(tmp_path / "test_users.db"))
    database.initialize_database()


def test_valid_username():
    assert validate_username("john_doe") is True


def test_invalid_username():
    assert validate_username("john doe!") is False


def test_username_too_short():
    assert validate_username("ab") is False


def test_strong_password():
    assert validate_password("Strong@123") is True


def test_weak_password():
    assert validate_password("password") is False


def test_password_hashing():
    stored = hash_password("Strong@123")
    assert stored != "Strong@123"
    assert verify_password("Strong@123", stored) is True


def test_wrong_password():
    stored = hash_password("Strong@123")
    assert verify_password("Wrong@123", stored) is False


def test_different_salts():
    assert hash_password("Strong@123") != hash_password("Strong@123")


def test_database_registration(temp_db):
    stored = hash_password("Strong@123")
    assert database.register_user("alice", stored) is True
    assert database.get_user("alice") == stored


def test_duplicate_username(temp_db):
    stored = hash_password("Strong@123")
    assert database.register_user("bob", stored) is True
    assert database.register_user("bob", stored) is False


def test_sql_injection_prevention(temp_db):
    stored = hash_password("Strong@123")
    database.register_user("carol", stored)
    assert database.get_user("' OR '1'='1' --") is None
    assert validate_username("' OR '1'='1' --") is False
    # The users table must still exist and work after the attack attempt.
    assert database.get_user("carol") == stored


def test_password_too_long_rejected():
    assert validate_password("Aa1!" + "x" * 200) is False