import os
import re
from functools import lru_cache
from config import SUSPICIOUS_DOMAINS_FILE


@lru_cache(maxsize=1)
def load_suspicious_domains() -> frozenset[str]:
    domains: set[str] = set()
    if not os.path.exists(SUSPICIOUS_DOMAINS_FILE):
        return frozenset()
    with open(SUSPICIOUS_DOMAINS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.add(line.lower())
    return frozenset(domains)


def is_suspicious(domain: str) -> bool:
    suspects = load_suspicious_domains()
    domain = domain.lower().rstrip(".")
    if domain in suspects:
        return True
    # Check parent domains: sub.evil.com → also match evil.com
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in suspects:
            return True
    return False


def reload():
    load_suspicious_domains.cache_clear()


_DGA_ENTROPY_THRESHOLD = 3.8


def _entropy(s: str) -> float:
    import math
    from collections import Counter
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# Simple heuristic: long, high-entropy second-level domain may be DGA
def looks_like_dga(domain: str) -> bool:
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False
    sld = parts[-2]  # second-level domain label
    if len(sld) < 12:
        return False
    vowel_ratio = sum(1 for c in sld.lower() if c in "aeiou") / len(sld)
    if vowel_ratio >= 0.20:
        return False  # enough vowels → probably pronounceable/legit
    return _entropy(sld) > _DGA_ENTROPY_THRESHOLD
