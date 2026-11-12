# Secure User Authentication System

A Python command-line application for user registration and login, built to demonstrate secure coding practices. It was developed for the Week 5 task: Security Enhancements in Python Applications.

Author: NANDHNI K S

## Features

- Parameterized SQL queries to prevent SQL injection
- Password hashing with PBKDF2-HMAC-SHA256, a random salt per user and 600,000 iterations
- Constant-time password comparison to prevent timing attacks
- Username validation (3-20 letters, numbers or underscores)
- Password strength rules (8-128 characters with uppercase, lowercase, number and special character)
- Generic error messages that do not leak system details
- Login lockout: 3 failed attempts blocks that username for 30 seconds
- Hidden password entry using `getpass`
- Automatic closing of database connections

## Project Structure

```
Python_Application_Security/
├── main.py              # Command-line menu (register, login, exit)
├── security.py          # Password hashing and input validation
├── database.py          # SQLite database functions
├── attack_demo.py       # SQL injection before/after demonstration
├── tests/
│   └── test_security.py # 12 automated tests
├── screenshots/         # Evidence screenshots
├── security_scan.json   # Ruff security scan result
├── requirements.txt
└── README.md
```

## Setup

1. Create and activate a virtual environment:

```
python -m venv venv
venv\Scripts\activate
```

2. Install the dependencies:

```
python -m pip install -r requirements.txt
```

## Run the Application

```
python main.py
```

## Run the Tests

```
python -m pytest -v
```

All 12 tests should pass.

## Run the Security Scan

```
python -m ruff check main.py security.py database.py --select S
```

Ruff's `S` rules (flake8-bandit) are used for security scanning.

## Run the Attack Demonstration

```
python attack_demo.py
```

This shows a SQL injection attack succeeding against a deliberately vulnerable query, and being blocked by the secured code.

## Security Audit Report

The full audit, with vulnerabilities, fixes, test results and screenshots, is in `Security_Audit_Report.docx`.