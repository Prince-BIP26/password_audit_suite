"""
password_analyzer.py

Checks a password's complexity, estimates entropy, flags common
dictionary weaknesses, and gives a few plain recommendations.
No hashing happens here, this just looks at the plaintext you give it.
"""

import math
import re

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein",
    "welcome", "admin", "iloveyou", "monkey", "football",
    "abc123", "111111", "password1", "12345678"
}

KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1qaz", "qazwsx"]


def _char_pool_size(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # rough estimate for common symbol set
    return pool or 1


def estimate_entropy(password):
    """Bits of entropy, assuming each character was picked at random
    from whatever character classes the password actually uses. This
    is a rough estimate, not a guarantee, real passwords are rarely
    truly random."""
    pool_size = _char_pool_size(password)
    bits = len(password) * math.log2(pool_size)
    return round(bits, 1)


def estimate_crack_time_seconds(entropy_bits, guesses_per_second=1_000_000_000):
    """Very rough offline brute-force estimate at a given guess rate.
    1 billion guesses/sec is a reasonable ballpark for a fast GPU rig
    against an unsalted, weak hash. Salted/slow hashes (bcrypt, argon2)
    would be dramatically slower, this is just for illustration."""
    total_combinations = 2 ** entropy_bits
    return total_combinations / guesses_per_second


def format_duration(seconds):
    if seconds < 1:
        return "under a second"
    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for label, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            return f"{value:,.1f} {label}"
    return "under a second"


def analyze(password):
    """Run the full check and return a dict the templates can render directly."""
    issues = []

    if len(password) < 8:
        issues.append("Password is shorter than 8 characters.")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most commonly breached passwords.")
    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters.")
    if not re.search(r"[a-z]", password):
        issues.append("No lowercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("No digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No symbols.")
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password.lower():
            issues.append(f"Contains a keyboard-walk pattern ('{pattern}').")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains a repeated character run (e.g. 'aaa').")
    if re.fullmatch(r"\d+", password):
        issues.append("Entirely numeric, trivial to brute force.")

    entropy = estimate_entropy(password)
    crack_seconds = estimate_crack_time_seconds(entropy)

    if entropy < 28:
        rating = "Very Weak"
    elif entropy < 36:
        rating = "Weak"
    elif entropy < 60:
        rating = "Reasonable"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return {
        "password_length": len(password),
        "entropy_bits": entropy,
        "rating": rating,
        "issues": issues,
        "crack_time_seconds": crack_seconds,
        "crack_time_readable": format_duration(crack_seconds),
    }
