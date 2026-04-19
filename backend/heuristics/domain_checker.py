class DomainChecker:

    # Confusable character mapping: digit/symbol -> the letter it mimics
    CONFUSABLES = str.maketrans({
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '6': 'g',
        '7': 't',
        '8': 'b',
        '|': 'l',
        '@': 'a',
    })

    # Known brand domain roots that attackers impersonate
    BRAND_DOMAINS = {
        'paypal', 'amazon', 'google', 'apple', 'microsoft',
        'netflix', 'facebook', 'instagram', 'whatsapp', 'twitter',
        'hsbc', 'barclays', 'lloyds', 'natwest', 'santander',
        'hdfc', 'sbi', 'icici', 'axis', 'kotak',
        'fedex', 'dhl', 'ups', 'usps', 'royalmail',
    }

    def __init__(self):
        self.malicious_domains = {
            # Known phishing/malicious domains
            "free-iphone-winner.com",
            "login-paypal-verify.com",
            "update-your-bank.us",
            "secure-msg.net",
            "parcel-track.xyz",
            "prize-claim.ml",
            # Malicious TLDs commonly used in smishing
            # (detected via suffix check in is_malicious)
            # Shortened URL services
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
        }

        self.malicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs abused by phishers
            '.xyz', '.top', '.click', '.loan', '.work',
            '.us',  # Frequently abused in smishing
        }

    def is_malicious(self, domain: str) -> bool:
        """
        Check if a domain is malicious by:
        1. Direct lookup in the known-bad domain list.
        2. Malicious TLD suffix check.
        3. Homograph / confusable-character detection against known brands.
        """
        domain = domain.lower().strip()

        if not domain or '.' not in domain:
            return False

        # 1. Direct list lookup
        if domain in self.malicious_domains:
            return True

        # 2. Malicious TLD check
        for tld in self.malicious_tlds:
            if domain.endswith(tld):
                return True

        # 3. Homograph detection
        if self._is_homograph_attack(domain):
            return True

        return False

    def _is_homograph_attack(self, domain: str) -> bool:
        """
        Detect digit/symbol substitution attacks against known brand domains.
        
        Example: "paypa1.com" -> translate "1" -> "l" -> "paypal" -> brand match.
        Only flags if the ORIGINAL domain is NOT already a brand domain 
        (to avoid false positives on the real domains).
        """
        # Extract the domain root (everything before the last dot)
        domain_root = domain.rsplit('.', 1)[0]

        # If it already exactly matches a brand, it's not a homograph attack
        if domain_root in self.BRAND_DOMAINS:
            return False

        # Translate confusable chars and check if it now matches a brand
        normalised = domain_root.translate(self.CONFUSABLES)
        return normalised in self.BRAND_DOMAINS
