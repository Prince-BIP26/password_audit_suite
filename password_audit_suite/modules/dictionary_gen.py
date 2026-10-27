"""
dictionary_gen.py

Builds custom wordlists from a few basic inputs: a name, a birth year,
some keywords, plus optional leet-speak and number-suffix mutations.

This is not meant to replace real tools like crunch or cupp, it's a
small teaching version so students can see how pattern-based wordlists
are actually put together.
"""

import itertools

# common substitutions used in "leet speak" mutations
LEET_MAP = {
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"
}

COMMON_SUFFIXES = ["", "1", "12", "123", "!", "01", "99", "2023", "2024", "2025"]
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "football", "abc123"
]


def leetify(word):
    """Return a leet-speak version of a word, swapping letters for digits."""
    out = []
    for ch in word.lower():
        out.append(LEET_MAP.get(ch, ch))
    return "".join(out)


def case_variants(word):
    """A handful of realistic casing patterns people actually use."""
    variants = {word.lower(), word.capitalize(), word.upper()}
    return list(variants)


def build_wordlist(name="", dob_year="", keywords=None, use_leet=True, use_common=True):
    """
    Build a wordlist from a name, a birth year and a list of keywords.

    Returns a sorted, de-duplicated list of candidate passwords. This
    mirrors the kind of pattern-based list generation a real attacker
    (or an auditor checking their own org's policy) would try before
    falling back to brute force.
    """
    keywords = keywords or []
    base_words = [w for w in ([name] + keywords) if w]

    candidates = set()

    for word in base_words:
        for cased in case_variants(word):
            for suffix in COMMON_SUFFIXES:
                candidates.add(f"{cased}{suffix}")
                if dob_year:
                    candidates.add(f"{cased}{dob_year}{suffix}")

            if use_leet:
                leet_word = leetify(word)
                for suffix in COMMON_SUFFIXES:
                    candidates.add(f"{leet_word}{suffix}")

    if use_common:
        for word in COMMON_PASSWORDS:
            for suffix in COMMON_SUFFIXES:
                candidates.add(f"{word}{suffix}")

    # drop anything under 4 characters, not realistic as a password guess
    cleaned = sorted(c for c in candidates if len(c) >= 4)
    return cleaned


def save_wordlist(wordlist, path):
    with open(path, "w") as f:
        for word in wordlist:
            f.write(word + "\n")
    return path
