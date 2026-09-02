# Password Strength Checker

A simple Python password strength checker.

## Requirements

The checker tests five conditions:

- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

The score is out of 5:

- 0–2: Weak
- 3–4: Moderate
- 5: Strong

## Run the program

```bash
python password_checker.py
```

## Run the tests

Install pytest if needed:

```bash
python -m pip install pytest
```

Then run:

```bash
python -m pytest -q
```

## Project structure

```text
password_strength_checker/
├── password_checker.py
├── test_password_checker.py
└── README.md
```
