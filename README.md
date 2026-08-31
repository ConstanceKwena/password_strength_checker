# password_strength_checker


A command-line password strength checker written in Python.

## Features

- **Basic checks**: length (≥8), uppercase, lowercase, digit, symbol
- **Blacklist check**: flags passwords found in a list of common/leaked passwords (`common_passwords.txt`)
- **Entropy scoring**: estimates password strength in bits using the standard `length × log2(pool_size)` formula
- **Have I Been Pwned integration**: optionally checks the password against known data breaches via the [HIBP k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords) — only a 5-character hash prefix is ever sent, never the password itself
- **Automated tests**: pytest suite covering all of the above (network calls are mocked, so tests run offline)

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python password_checker.py
```

You'll be prompted to enter a password, then shown a breakdown of which checks it passes, an overall strength rating, an entropy estimate, and (optionally) whether it's appeared in a known breach.

## Running the tests

```bash
pytest -v
```

## Project structure

```
password_checker.py       # main script + all logic (importable functions)
common_passwords.txt      # blacklist of common passwords
test_password_checker.py  # pytest test suite
requirements.txt
```
