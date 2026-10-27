"""
cracker_demo.py

Two things live here:

1. A shadow-file FORMAT parser. It reads a sample /etc/shadow-style
   text file (bundled under sample_data/) and explains each field.
   It does NOT touch a real system's /etc/shadow or pull a live
   Windows SAM hive, this project only ever works on the sample file
   you give it, so it's safe to run anywhere.

2. A small dictionary-attack simulator. You give it a hash (one you
   generated yourself, for example with hash_a_password() below) and
   a wordlist, and it times how long a straight dictionary pass takes.
   It's a teaching tool for understanding why weak passwords fall
   fast, not a general-purpose cracking rig.
"""

import hashlib
import time

SUPPORTED_ALGOS = {
    "md5": hashlib.md5,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def hash_a_password(password, algo="sha256"):
    """Hash a password you provide, so you have something safe to test
    the cracker against. This never reads passwords from a real system."""
    fn = SUPPORTED_ALGOS.get(algo)
    if fn is None:
        raise ValueError(f"Unsupported algorithm: {algo}")
    return fn(password.encode()).hexdigest()


def dictionary_attack(target_hash, wordlist, algo="sha256"):
    """
    Try every word in wordlist against target_hash.
    Returns (found_password_or_None, attempts_tried, elapsed_seconds).
    """
    fn = SUPPORTED_ALGOS.get(algo)
    if fn is None:
        raise ValueError(f"Unsupported algorithm: {algo}")

    start = time.time()
    attempts = 0
    for candidate in wordlist:
        attempts += 1
        if fn(candidate.encode()).hexdigest() == target_hash:
            elapsed = time.time() - start
            return candidate, attempts, elapsed

    elapsed = time.time() - start
    return None, attempts, elapsed


def parse_sample_shadow(path):
    """
    Parse a sample shadow-format file (colon separated, same layout as
    a real Linux /etc/shadow entry) and return the fields broken out
    so the format can be explained on screen.

    Fields: username : hash : last_change : min : max : warn : inactive : expire
    """
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue

            username = parts[0]
            hash_field = parts[1]

            if hash_field in ("", "*", "!", "!!"):
                algo_tag, note = "none", "Account has no password set or login is disabled."
            elif hash_field.startswith("$6$"):
                algo_tag, note = "SHA-512 (crypt)", "Modern Linux default, salted and slow to brute force."
            elif hash_field.startswith("$5$"):
                algo_tag, note = "SHA-256 (crypt)", "Salted, reasonably strong."
            elif hash_field.startswith("$1$"):
                algo_tag, note = "MD5 (crypt)", "Outdated, considered weak by modern standards."
            else:
                algo_tag, note = "unknown", "Unrecognized hash format."

            entries.append({
                "username": username,
                "hash": hash_field,
                "algorithm": algo_tag,
                "note": note,
            })
    return entries
