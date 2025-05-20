import re
from microservices.attack_patterns import ATTACK_PATTERNS as  ATTACK_PATTERNS_ENHANCED

def test_regex_patterns():
    for threat_type, patterns in ATTACK_PATTERNS_ENHANCED.items():
        print(f"Testing patterns for {threat_type}")
        for i, pattern in enumerate(patterns):
            try:
                re.compile(pattern, re.IGNORECASE)
                print(f"  Pattern {i}: OK")
            except re.PatternError as e:
                print(f"  Pattern {i}: ERROR - {e}")
                print(f"    Pattern content: {pattern}")
                print(f"    Error position: {e.pos}")
                return  # Stop at first error for focus

if __name__ == "__main__":
    test_regex_patterns()