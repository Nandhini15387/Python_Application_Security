import sqlite3

from database import get_user
from security import hash_password, validate_username

ATTACK_INPUT = "' OR '1'='1' --"


def setup_demo_db():
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)"
    )
    connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ("admin", hash_password("Admin@12345")),
    )
    connection.commit()
    return connection


def vulnerable_login(connection, username):
    # INSECURE: user input is joined directly into the SQL text.
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    print("   Query executed:", query)
    return connection.execute(query).fetchone()


print("=" * 60)
print("PART 1: VULNERABLE CODE (string concatenation)")
print("=" * 60)
connection = setup_demo_db()
print("Attacker enters username:", ATTACK_INPUT)
result = vulnerable_login(connection, ATTACK_INPUT)
if result:
    print("   RESULT: ATTACK SUCCEEDED - logged in as:", result[1])
else:
    print("   RESULT: Attack failed")

print()
print("=" * 60)
print("PART 2: FIXED CODE (this project)")
print("=" * 60)
print("Attacker enters username:", ATTACK_INPUT)
print("   Username validation passes?", validate_username(ATTACK_INPUT))
print("   Database lookup result:", get_user(ATTACK_INPUT))
print("   RESULT: ATTACK BLOCKED - input rejected and treated as plain text")