"""
CyberGuard Password Security Analyzer & Cryptographic Generator.

Evaluates password strength using information entropy, character diversity,
structural pattern heuristics (repetition and keyboard sequences), and local
dictionary analysis without ever logging or transmitting passwords.
"""

import math
import re
import secrets
import string
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from config import (
    COMMON_WEAK_PASSWORDS,
    ENTROPY_THRESHOLDS,
    MIN_PASSWORD_LENGTH,
    RECOMMENDED_PASSWORD_LENGTH,
)
from core.logger import get_logger

logger = get_logger("password_analyzer")

# Built-in educational wordlist for secure passphrase generation
PASSPHRASE_WORDS: List[str] = [
    "amber", "anchor", "beacon", "breeze", "castle", "cipher", "cobalt",
    "comet", "canyon", "drift", "ember", "falcon", "forest", "glacier",
    "granite", "harbor", "island", "jaguar", "keeper", "lantern", "matrix",
    "meadow", "nexus", "oasis", "orbit", "pathway", "phantom", "pillar",
    "quantum", "radar", "radius", "raven", "ridge", "safari", "satellite",
    "shadow", "shield", "silver", "solace", "spiral", "summit", "timber",
    "titan", "torrent", "tower", "tracer", "vanguard", "velvet", "vessel",
    "voyage", "walnut", "zenith"
]

COMMON_SEQUENCES: List[str] = [
    "0123456789",
    "9876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


@dataclass
class PasswordAnalysisResult:
    """Detailed diagnostic results of password security evaluation."""
    length: int
    score: int
    risk_level: str
    nist_entropy_bits: float
    shannon_entropy_bits: float
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    diversity_count: int
    is_dictionary_match: bool
    has_repetitive_pattern: bool
    has_sequential_pattern: bool
    identified_patterns: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Convert results to serializable dictionary without exposing plain text."""
        return {
            "length": self.length,
            "score": self.score,
            "risk_level": self.risk_level,
            "nist_entropy_bits": round(self.nist_entropy_bits, 2),
            "shannon_entropy_bits": round(self.shannon_entropy_bits, 2),
            "character_diversity": {
                "uppercase": self.has_uppercase,
                "lowercase": self.has_lowercase,
                "digits": self.has_digits,
                "special": self.has_special,
                "diversity_count": self.diversity_count,
            },
            "heuristics": {
                "is_dictionary_match": self.is_dictionary_match,
                "has_repetitive_pattern": self.has_repetitive_pattern,
                "has_sequential_pattern": self.has_sequential_pattern,
                "patterns": self.identified_patterns,
            },
            "recommendations": self.recommendations,
        }


class PasswordAnalyzer:
    """Defensive security analyzer for credential complexity and randomness."""

    @staticmethod
    def calculate_pool_size(password: str) -> int:
        """Determines the size of the possible character pool (R)."""
        pool = 0
        if re.search(r"[a-z]", password):
            pool += 26
        if re.search(r"[A-Z]", password):
            pool += 26
        if re.search(r"[0-9]", password):
            pool += 10
        if re.search(r"""[!@#$%^&*()_+\-=\[\]{}|;':",.<>?/`~\\ ]""", password):
            pool += 33
        return pool

    @classmethod
    def calculate_nist_entropy(cls, password: str) -> float:
        """Calculates theoretical NIST pool entropy: E = L * log2(R)."""
        if not password:
            return 0.0
        pool_size = cls.calculate_pool_size(password)
        if pool_size == 0:
            return 0.0
        return len(password) * math.log2(pool_size)

    @staticmethod
    def calculate_shannon_entropy(password: str) -> float:
        """Calculates Shannon information entropy of the password string."""
        if not password:
            return 0.0
        length = len(password)
        frequencies: Dict[str, int] = {}
        for char in password:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy = 0.0
        for count in frequencies.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy * length

    @staticmethod
    def detect_repetitive_patterns(password: str) -> Tuple[bool, List[str]]:
        """Identifies repeated character chunks (e.g. 'aaa', '1111')."""
        patterns: List[str] = []
        if re.search(r"(.)\1{2,}", password):
            patterns.append("Three or more consecutive identical characters.")
        # Repeated 2-char blocks like 'ababab'
        if re.search(r"(.{2,3})\1{2,}", password):
            patterns.append("Repeated repeating character sequences.")
        return len(patterns) > 0, patterns

    @staticmethod
    def detect_sequential_patterns(password: str) -> Tuple[bool, List[str]]:
        """Identifies sequential keyboard or alphabetical sequences (e.g., '12345', 'qwerty')."""
        lower_pwd = password.lower()
        patterns: List[str] = []

        for seq in COMMON_SEQUENCES:
            for i in range(len(seq) - 3):
                window = seq[i : i + 4]
                if window in lower_pwd:
                    patterns.append(f"Sequential run detected ('{window}').")
                    break

        return len(patterns) > 0, patterns

    @staticmethod
    def check_common_dictionary(password: str) -> bool:
        """Verifies if password or normalized substring exists in weak dictionary."""
        lower = password.strip().lower()
        return lower in COMMON_WEAK_PASSWORDS

    @classmethod
    def analyze(cls, password: str) -> PasswordAnalysisResult:
        """
        Executes complete security analysis on password.
        Note: The password string is processed in memory and never logged or persisted.
        """
        logger.info("Evaluating password security strength (length: %d chars)", len(password))

        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digits = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r"""[!@#$%^&*()_+\-=\[\]{}|;':",.<>?/`~\\ ]""", password))

        diversity_count = sum([has_upper, has_lower, has_digits, has_special])
        nist_entropy = cls.calculate_nist_entropy(password)
        shannon_entropy = cls.calculate_shannon_entropy(password)

        is_dict_match = cls.check_common_dictionary(password)
        has_repeat, repeat_patterns = cls.detect_repetitive_patterns(password)
        has_seq, seq_patterns = cls.detect_sequential_patterns(password)

        all_patterns = repeat_patterns + seq_patterns
        if is_dict_match:
            all_patterns.append("Identified in known educational weak password dictionary.")

        # Compute Score (0 - 100)
        score = 0
        recommendations: List[str] = []

        # Length component (up to 50 pts)
        if length >= 16:
            score += 50
        elif length >= 12:
            score += 35
        elif length >= 8:
            score += 20
        else:
            score += max(0, length * 2)
            recommendations.append(f"Increase length to at least {MIN_PASSWORD_LENGTH} characters (preferably 16+).")

        # Character diversity component (up to 30 pts)
        score += diversity_count * 7.5
        if not has_upper:
            recommendations.append("Include uppercase characters (A-Z).")
        if not has_lower:
            recommendations.append("Include lowercase characters (a-z).")
        if not has_digits:
            recommendations.append("Include numbers (0-9).")
        if not has_special:
            recommendations.append("Include special characters (!@#$%^&*).")

        # Entropy bonus (up to 20 pts)
        if nist_entropy >= ENTROPY_THRESHOLDS["STRONG"]:
            score += 20
        elif nist_entropy >= ENTROPY_THRESHOLDS["MODERATE"]:
            score += 12
        elif nist_entropy >= ENTROPY_THRESHOLDS["WEAK"]:
            score += 5
        else:
            recommendations.append("Increase character randomness to prevent brute-force dictionary attacks.")

        # Pattern Deductions
        if has_repeat:
            score -= 15
            recommendations.append("Avoid repeated consecutive characters.")
        if has_seq:
            score -= 15
            recommendations.append("Avoid sequential keyboard runs (e.g. '1234', 'qwerty').")

        # Severe penalty for common dictionary hits
        if is_dict_match:
            score = min(score, 5)
            recommendations.append("CRITICAL: This is a universally known default password. Change immediately.")

        # Cap based on length
        if length < 6:
            score = min(score, 10)
        elif length < 8:
            score = min(score, 30)

        final_score = int(max(0, min(100, round(score))))

        # Determine Risk Level
        if final_score >= 85:
            risk_level = "MINIMAL"
        elif final_score >= 70:
            risk_level = "LOW"
        elif final_score >= 50:
            risk_level = "MEDIUM"
        elif final_score >= 30:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        if not recommendations:
            recommendations.append("Excellent password complexity. Follow regular rotation and use a password manager.")

        return PasswordAnalysisResult(
            length=length,
            score=final_score,
            risk_level=risk_level,
            nist_entropy_bits=nist_entropy,
            shannon_entropy_bits=shannon_entropy,
            has_uppercase=has_upper,
            has_lowercase=has_lower,
            has_digits=has_digits,
            has_special=has_special,
            diversity_count=diversity_count,
            is_dictionary_match=is_dict_match,
            has_repetitive_pattern=has_repeat,
            has_sequential_pattern=has_seq,
            identified_patterns=all_patterns,
            recommendations=recommendations,
        )

    @staticmethod
    def generate_secure_password(
        length: int = 16,
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_special: bool = True,
    ) -> str:
        """
        Generates a cryptographically strong random password using secrets module.
        Ensures at least one character from each selected class is present.
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters.")

        character_sets: List[str] = []
        guaranteed_chars: List[str] = []

        if include_upper:
            character_sets.append(string.ascii_uppercase)
            guaranteed_chars.append(secrets.choice(string.ascii_uppercase))
        if include_lower:
            character_sets.append(string.ascii_lowercase)
            guaranteed_chars.append(secrets.choice(string.ascii_lowercase))
        if include_digits:
            character_sets.append(string.digits)
            guaranteed_chars.append(secrets.choice(string.digits))
        if include_special:
            specials = "!@#$%^&*()-_=+[]{}?"
            character_sets.append(specials)
            guaranteed_chars.append(secrets.choice(specials))

        if not character_sets:
            raise ValueError("At least one character class must be enabled.")

        combined_pool = "".join(character_sets)
        remaining_length = length - len(guaranteed_chars)
        random_chars = [secrets.choice(combined_pool) for _ in range(remaining_length)]

        full_password = guaranteed_chars + random_chars
        # Cryptographically shuffle character array
        shuffled = list(full_password)
        # Fisher-Yates shuffle using secrets.randbelow
        for i in range(len(shuffled) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

        return "".join(shuffled)

    @staticmethod
    def generate_passphrase(words_count: int = 4, separator: str = "-") -> str:
        """
        Generates an EFF/Diceware-style multi-word passphrase using secrets.choice.
        """
        if words_count < 3:
            raise ValueError("Passphrase should consist of at least 3 words for security.")
        chosen_words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(words_count)]
        return separator.join(chosen_words)
