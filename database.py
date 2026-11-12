import sqlite3
from contextlib import closing

DATABASE_NAME = "users.db"


def get_connection():
    """Create a connection to the SQLite database."""
    return sqlite3.connect(DATABASE_NAME)


def initialize_database():
    """Create the users table if it does not exist."""

    try:
        with closing(get_connection()) as connection:
            with connection:  # commits on success, rolls back on error
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL
                    )
                """)

    except sqlite3.Error:
        raise RuntimeError("Database initialization failed.")


def register_user(username, password_hash):
    """Register a new user securely."""

    try:
        with closing(get_connection()) as connection:
            with connection:
                # Parameterized query prevents SQL injection.
                connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
        return True

    except sqlite3.IntegrityError:
        return False

    except sqlite3.Error:
        raise RuntimeError("Unable to register user.")


def get_user(username):
    """Retrieve a user's password hash."""

    try:
        with closing(get_connection()) as connection:
            # Parameterized query prevents SQL injection.
            result = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        return result[0] if result else None

    except sqlite3.Error:
        raise RuntimeError("Unable to retrieve user information.")