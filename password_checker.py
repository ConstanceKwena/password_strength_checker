import re
import sys


def check_password(password: str) -> dict:
    results = {
        "length_ok": len(password) >= 8,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_symbol": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
    }
    results["score"] = sum(1 for v in results.values() if v is True)
    return results


def strength_label(score: int) -> str:
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Moderate"
    return "Strong"


def main():
    password = input("Enter a password to check: ")
    results = check_password(password)

    print("\n--- Password Check ---")
    print(f"Length >= 8:   {'✔' if results['length_ok'] else '✘'}")
    print(f"Uppercase:     {'✔' if results['has_upper'] else '✘'}")
    print(f"Lowercase:     {'✔' if results['has_lower'] else '✘'}")
    print(f"Digit:         {'✔' if results['has_digit'] else '✘'}")
    print(f"Symbol:        {'✔' if results['has_symbol'] else '✘'}")
    print(f"\nStrength: {strength_label(results['score'])} ({results['score']}/5)")


if __name__ == "__main__":
    main()