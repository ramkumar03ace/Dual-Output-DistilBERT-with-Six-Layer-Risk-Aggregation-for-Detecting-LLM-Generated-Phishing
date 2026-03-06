"""
Sender analysis — checks email header metadata for legitimacy.

Analyzes:
- Domain mismatches (from vs mailed-by vs signed-by)
- Display name spoofing
- Lookalike/typosquat domains
- Free email providers impersonating brands
- Missing DKIM/TLS
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)

# Well-known free email providers
FREE_PROVIDERS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'aol.com', 'icloud.com', 'me.com', 'mac.com',
    'protonmail.com', 'proton.me', 'zoho.com',
    'yandex.com', 'mail.com', 'gmx.com', 'tutanota.com',
    'rediffmail.com', 'fastmail.com',
}

# Brand names commonly spoofed in display names
BRAND_NAMES = {
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    'dropbox', 'adobe', 'dhl', 'fedex', 'ups', 'usps',
    'spotify', 'zoom', 'slack', 'github', 'stripe',
}

# Common character substitutions for lookalike domains
LOOKALIKE_MAP = {
    '0': 'o', 'o': '0',
    '1': 'l', 'l': '1',
    'i': 'l', 'l': 'i',
    'rn': 'm',
    'vv': 'w',
    '5': 's', 's': '5',
}


@dataclass
class SenderAnalysisResult:
    """Result of sender header analysis."""
    is_suspicious: bool = False
    risk_score: float = 0.0
    flags: List[str] = field(default_factory=list)


class SenderAnalyzer:
    """Analyzes email sender metadata for legitimacy."""

    def analyze(
        self,
        from_name: Optional[str] = None,
        from_email: Optional[str] = None,
        mailed_by: Optional[str] = None,
        signed_by: Optional[str] = None,
        security: Optional[str] = None,
    ) -> SenderAnalysisResult:
        """
        Analyze sender header metadata.

        Args:
            from_name: Display name (e.g., "Ranjith R")
            from_email: Sender email (e.g., "ranjith@vit.ac.in")
            mailed_by: Mailed-by domain (e.g., "vit.ac.in")
            signed_by: Signed-by / DKIM domain (e.g., "vit.ac.in")
            security: Security info (e.g., "Standard encryption (TLS)")

        Returns:
            SenderAnalysisResult with risk score and flags
        """
        flags = []
        risk_score = 0.0

        if not from_email:
            return SenderAnalysisResult()

        from_email = from_email.strip().lower()
        from_domain = self._extract_domain(from_email)
        from_name = (from_name or '').strip()

        if not from_domain:
            flags.append("Could not extract sender domain")
            return SenderAnalysisResult(
                is_suspicious=True, risk_score=0.3, flags=flags
            )

        # --------------------------------------------------
        # CHECK 1: Domain mismatch (from vs mailed-by)
        # --------------------------------------------------
        if mailed_by:
            mailed_by_clean = mailed_by.strip().lower()
            if mailed_by_clean and mailed_by_clean != from_domain:
                # Check if it's a subdomain relationship
                if not (mailed_by_clean.endswith('.' + from_domain) or
                        from_domain.endswith('.' + mailed_by_clean)):
                    flags.append(
                        f"Domain mismatch: from @{from_domain} but mailed-by {mailed_by_clean}"
                    )
                    risk_score += 0.35

        # --------------------------------------------------
        # CHECK 2: DKIM signature mismatch or missing
        # --------------------------------------------------
        if signed_by:
            signed_by_clean = signed_by.strip().lower()
            if signed_by_clean and signed_by_clean != from_domain:
                if not (signed_by_clean.endswith('.' + from_domain) or
                        from_domain.endswith('.' + signed_by_clean)):
                    flags.append(
                        f"DKIM mismatch: from @{from_domain} but signed-by {signed_by_clean}"
                    )
                    risk_score += 0.25
        else:
            # No DKIM signature at all
            flags.append("No DKIM signature (signed-by missing)")
            risk_score += 0.15

        # --------------------------------------------------
        # CHECK 3: No TLS encryption
        # --------------------------------------------------
        if security:
            security_lower = security.strip().lower()
            if 'tls' not in security_lower and 'encrypt' not in security_lower:
                flags.append(f"Weak or no encryption: {security}")
                risk_score += 0.15
        else:
            flags.append("No encryption information available")
            risk_score += 0.10

        # --------------------------------------------------
        # CHECK 4: Display name spoofing
        # --------------------------------------------------
        if from_name:
            name_lower = from_name.lower().replace(' ', '')
            # Check if display name contains a brand but email is from a free provider
            for brand in BRAND_NAMES:
                if brand in name_lower and from_domain in FREE_PROVIDERS:
                    flags.append(
                        f"Display name contains '{brand}' but sent from free provider @{from_domain}"
                    )
                    risk_score += 0.40
                    break

            # Check if display name contains an email from a different domain
            name_emails = re.findall(
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                from_name
            )
            for ne in name_emails:
                ne_domain = self._extract_domain(ne)
                if ne_domain and ne_domain != from_domain:
                    flags.append(
                        f"Display name contains email @{ne_domain} but actual sender is @{from_domain}"
                    )
                    risk_score += 0.30

        # --------------------------------------------------
        # CHECK 5: Free email provider for business-looking emails
        # --------------------------------------------------
        if from_domain in FREE_PROVIDERS:
            flags.append(f"Sent from free email provider (@{from_domain})")
            risk_score += 0.05  # Mild flag — common but worth noting

        # --------------------------------------------------
        # CHECK 6: Lookalike / typosquat domain
        # --------------------------------------------------
        lookalike = self._check_lookalike(from_domain)
        if lookalike:
            flags.append(
                f"Possible lookalike domain: @{from_domain} resembles '{lookalike}'"
            )
            risk_score += 0.40

        # Clamp to [0, 1]
        risk_score = min(1.0, risk_score)

        return SenderAnalysisResult(
            is_suspicious=risk_score >= 0.25,
            risk_score=round(risk_score, 4),
            flags=flags,
        )

    @staticmethod
    def _extract_domain(email: str) -> Optional[str]:
        """Extract domain from an email address."""
        if '@' in email:
            return email.split('@')[-1].strip().lower()
        return email.strip().lower() if email else None

    @staticmethod
    def _check_lookalike(domain: str) -> Optional[str]:
        """Check if domain looks like a typosquat of a known brand."""
        # Strip TLD for comparison
        base = domain.split('.')[0].lower()

        for brand in BRAND_NAMES:
            if base == brand:
                continue  # Exact match = legit

            # Check edit distance of 1-2
            if len(base) == len(brand):
                diff = sum(1 for a, b in zip(base, brand) if a != b)
                if 1 <= diff <= 2:
                    return brand

            # Check common substitutions
            normalized = base
            for fake, real in LOOKALIKE_MAP.items():
                normalized = normalized.replace(fake, real)
            if normalized == brand and normalized != base:
                return brand

        return None


# Global instance
sender_analyzer = SenderAnalyzer()
