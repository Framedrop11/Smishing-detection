import re
from preprocessing.url_processor import extract_urls, normalize_url


class RuleEngine:

    def __init__(self):
        self.short_url_domains = [
            'bit.ly', 'tinyurl.com', 'is.gd', 'goo.gl', 't.co', 'ow.ly'
        ]

        # FIX 1: Replace flat keyword list with compiled regex patterns.
        # Each pattern uses word boundaries (\b) and allows optional filler
        # words between key terms (e.g. "account has been suspended").
        # Use re.IGNORECASE so we don't need to lowercase first.
        self.urgency_patterns = [
            (re.compile(r'\burgent\b', re.IGNORECASE),
             "Urgency keyword detected: 'urgent'"),

            (re.compile(r'\bverif(y|ication|ied)\b', re.IGNORECASE),
             "Urgency keyword detected: 'verify'"),

            (re.compile(r'\bclick\s+now\b', re.IGNORECASE),
             "Urgency keyword detected: 'click now'"),

            # FIX: was "account suspended" — now matches "account has been suspended" etc.
            (re.compile(r'\baccount\b.{0,20}\bsuspended\b', re.IGNORECASE),
             "Urgency keyword detected: 'account suspended'"),

            (re.compile(r'\bbeen\s+suspended\b', re.IGNORECASE),
             "Urgency keyword detected: 'account suspended'"),

            (re.compile(r'\baction\s+required\b', re.IGNORECASE),
             "Urgency keyword detected: 'action required'"),

            (re.compile(r'\bwinner\b', re.IGNORECASE),
             "Urgency keyword detected: 'winner'"),

            (re.compile(r'\bwon\b', re.IGNORECASE),
             "Urgency keyword detected: 'won'"),

            (re.compile(r'\bclaim\s+your\s+prize\b', re.IGNORECASE),
             "Urgency keyword detected: 'claim your prize'"),

            (re.compile(r'\bimmediate\s+action\b', re.IGNORECASE),
             "Urgency keyword detected: 'immediate action'"),

            (re.compile(r'\bsecurity\s+alert\b', re.IGNORECASE),
             "Urgency keyword detected: 'security alert'"),

            (re.compile(r'\bupdate\s+now\b', re.IGNORECASE),
             "Urgency keyword detected: 'update now'"),

            (re.compile(r'\bpassword\s+reset\b', re.IGNORECASE),
             "Urgency keyword detected: 'password reset'"),
        ]

        # FIX 2: New — PII harvesting pattern detection.
        # Catches credential-harvesting messages that have no URL and no
        # urgency keywords (Test T16 failure).
        self.pii_patterns = [
            (re.compile(r'\bdate\s+of\s+birth\b', re.IGNORECASE),
             "PII harvesting detected: 'date of birth'"),

            (re.compile(r'\bcard\b.{0,15}\bnumber\b', re.IGNORECASE),
             "PII harvesting detected: 'card number'"),

            (re.compile(r'\bcredit\s+card\b', re.IGNORECASE),
             "PII harvesting detected: 'credit card'"),

            (re.compile(r'\bdebit\s+card\b', re.IGNORECASE),
             "PII harvesting detected: 'debit card'"),

            (re.compile(r'\bsocial\s+security\b', re.IGNORECASE),
             "PII harvesting detected: 'social security'"),

            (re.compile(r'\baccount\s+number\b', re.IGNORECASE),
             "PII harvesting detected: 'account number'"),

            (re.compile(r'\bsort\s+code\b', re.IGNORECASE),
             "PII harvesting detected: 'sort code'"),

            (re.compile(r'\bcvv\b|\bcvc\b', re.IGNORECASE),
             "PII harvesting detected: 'cvv'"),

            (re.compile(r'\bfull\s+name\b.{0,40}\bdate\s+of\s+birth\b', re.IGNORECASE),
             "PII harvesting detected: personal data request"),

            (re.compile(r'\bpin\s+(number|code)\b', re.IGNORECASE),
             "PII harvesting detected: 'PIN'"),
        ]

        # Phone number pattern — unchanged
        self.suspicious_number_pattern = (
            r'(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
        )

    def evaluate(self, text: str) -> dict:
        """
        Evaluates the text against heuristic rules.
        Returns a dict: {'is_smishing': bool, 'reason': str}
        """
        # 1. Presence of shortened URLs
        urls = extract_urls(text)
        for url in urls:
            domain = normalize_url(url)
            if domain in self.short_url_domains:
                return {"is_smishing": True, "reason": "Shortened URL detected"}

        # 2. Urgency patterns (regex-based, replaces flat keyword list)
        for pattern, reason in self.urgency_patterns:
            if pattern.search(text):
                return {"is_smishing": True, "reason": reason}

        # 3. PII harvesting patterns (new)
        for pattern, reason in self.pii_patterns:
            if pattern.search(text):
                return {"is_smishing": True, "reason": reason}

        # 4. Multiple suspicious phone numbers
        num_matches = re.findall(self.suspicious_number_pattern, text)
        if len(num_matches) >= 2:
            return {
                "is_smishing": True,
                "reason": "Multiple suspicious phone numbers detected"
            }

        return {"is_smishing": False, "reason": ""}
