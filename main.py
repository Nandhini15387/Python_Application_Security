import getpass
import time

from database import initialize_database, register_user, get_user
from security import (
    hash_password,
    verify_password,
    validate_username,
    validate_password
)

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 30
failed_attempts = {}  # username -> (count, last_failure_time)


def main():
    initialize_database()

    print("\n===== SECURE USER AUTHENTICATION SYSTEM =====")

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")

            if not validate_username(username):
                print("Invalid username. Use 3-20 letters, numbers or underscores.")
                continue

            if not validate_password(password):
                print("Weak password. Use 8-128 characters with uppercase, lowercase, number and special character.")
                continue

            password_hash = hash_password(password)

            try:
                if register_user(username, password_hash):
                    print("Registration successful!")
                else:
                    print("Username already exists.")

            except RuntimeError:
                print("Registration failed due to a system error.")

        elif choice == "2":
            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")

            count, last_time = failed_attempts.get(username, (0, 0))

            if count >= MAX_ATTEMPTS and time.time() - last_time < LOCKOUT_SECONDS:
                print("Too many failed attempts. Try again later.")
                continue

            if count >= MAX_ATTEMPTS:
                count = 0  # lockout period is over

            try:
                stored_hash = get_user(username)

                if stored_hash and verify_password(password, stored_hash):
                    failed_attempts.pop(username, None)
                    print("Login successful! Welcome,", username)
                else:
                    failed_attempts[username] = (count + 1, time.time())
                    print("Invalid username or password.")

            except RuntimeError:
                print("Login failed due to a system error.")

        elif choice == "3":
            print("Thank you for using the application!")
            break

        else:
            print("Invalid choice. Please select 1, 2 or 3.")


if __name__ == "__main__":
    main()