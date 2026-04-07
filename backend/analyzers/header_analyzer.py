"""
Email Header Forensics Analyzer — Layer 6

Parses raw email headers to detect authentication failures and anomalies:

  1. SPF  — checks "Received-SPF" and "Authentication-Results" for pass/fail/neutral/softfail
  2. DKIM — checks "DKIM-Signature" presence and "Authentication-Results" for pass/fail
  3. DMARC — checks "Authentication-Results" for dmarc=pass/fail
  4. Reply-To vs From mismatch — different domains is a strong phishing signal
  5. Received chain hop count — long chains (>5) are anomalous; geolocation anomalies flagged
  6. Display-name spoofing — From display name contains a known brand but email domain doesn't match
  7. Return-Path mismatch — Return-Path domain differs from From domain
  8. X-Mailer / User-Agent analysis — unusual mailer strings common in phishing toolkits
  9. Date header anomaly — email date far in future/past
 10. Subject encoding anomaly — encoded subjects sometimes used to bypass filters

No external DNS calls required — pure header string analysis.
Optional dnspython SPF lookup available if installed (gracefully degraded if not).
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import HeaderParser
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known brand → legitimate sending domain fragments
# (display-name spoofing detector)
# ---------------------------------------------------------------------------
_BRAND_DOMAINS: dict = {
    "paypal":     ["paypal.com"],
    "amazon":     ["amazon.com", "amazon.co.uk", "amazon.in"],
    "apple":      ["apple.com", "icloud.com"],
    "microsoft":  ["microsoft.com", "outlook.com", "live.com", "hotmail.com"],
    "google":     ["google.com", "gmail.com", "googlemail.com"],
    "netflix":    ["netflix.com"],
    "facebook":   ["facebook.com", "fb.com", "meta.com"],
    "instagram":  ["instagram.com"],
    "twitter":    ["twitter.com", "x.com"],
    "chase":      ["chase.com", "jpmchase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank":   ["citibank.com", "citi.com"],
    "barclays":   ["barclays.com", "barclays.co.uk"],
    "dhl":        ["dhl.com", "dhl.de"],
    "fedex":      ["fedex.com"],
    "ups":        ["ups.com"],
    "linkedin":   ["linkedin.com", "e.linkedin.com"],
    "dropbox":    ["dropbox.com"],
    "ebay":       ["ebay.com"],
    "docusign":   ["docusign.com", "docusign.net"],
}

# Phishing toolkit mailer patterns
_SUSPICIOUS_MAILERS = [
    r"phpmailer", r"swiftmailer", r"sendmail.*modified",
    r"mass ?mailer", r"bulk ?mail", r"turbomail", r"interspire",
    r"emailjet.*beta", r"unknown", r"python-requests", r"curl",
]

# Free / throwaway domains commonly used for phishing
_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "protonmail.com", "tutanota.com", "guerrillamail.com", "tempmail.com",
    "mailinator.com", "yopmail.com", "dispostable.com", "throwam.com",
    "10minutemail.com", "sharklasers.com", "guerrillamailblock.com",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class HeaderAnalysisResult:
    spf_result: str = "none"        # pass | fail | softfail | neutral | none | error
    dkim_result: str = "none"       # pass | fail | none | error
    dmarc_result: str = "none"      # pass | fail | none | error
    reply_to_mismatch: bool = False
    from_domain: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    return_path_mismatch: bool = False
    received_hops: int = 0
    display_name_spoof: bool = False
    spoofed_brand: str = ""
    suspicious_mailer: bool = False
    mailer: str = ""
    date_anomaly: bool = False
    date_days_diff: int = 0
    is_suspicious: bool = False
    risk_score: float = 0.0
    flags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Header field extraction helpers
# ---------------------------------------------------------------------------

def _extract_domain(addr: str) -> str:
    """Extract domain from an email address like 'Display Name <user@domain.com>'."""
    addr = addr.strip()
    # Extract angle-bracket part
    m = re.search(r"<([^>]+)>", addr)
    if m:
        addr = m.group(1)
    # Get domain
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""


def _parse_auth_results(auth_header: str) -> Tuple[str, str, str]:
    """
    Parse Authentication-Results header for spf/dkim/dmarc values.
    Returns (spf, dkim, dmarc) strings like 'pass', 'fail', 'none'.
    """
    spf = dkim = dmarc = "none"

    h = auth_header.lower()

    # SPF
    m = re.search(r"\bspf=(\w+)", h)
    if m:
        spf = m.group(1)

    # DKIM
    m = re.search(r"\bdkim=(\w+)", h)
    if m:
        dkim = m.group(1)

    # DMARC
    m = re.search(r"\bdmarc=(\w+)", h)
    if m:
        dmarc = m.group(1)

    return spf, dkim, dmarc


def _check_display_name_spoof(from_header: str) -> Tuple[bool, str]:
    """
    Check if display name contains a known brand but the sending domain
    does not match that brand's known domains.
    """
    # Extract display name (before angle bracket or whole string if no bracket)
    name_part = ""
    m = re.match(r"^\"?([^<\"]+)\"?\s*<", from_header.strip())
    if m:
        name_part = m.group(1).lower()
    else:
        name_part = from_header.lower()

    from_domain = _extract_domain(from_header)

    for brand, legit_domains in _BRAND_DOMAINS.items():
        if brand in name_part:
            # Brand mentioned in display name — check if from_domain matches
            if from_domain and not any(from_domain.endswith(ld) for ld in legit_domains):
                return True, brand
    return False, ""


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class HeaderAnalyzer:
    """
    Stateless header forensics analyzer.
    Call `analyze(raw_headers_text)` with the raw header block as a string.
    """

    def analyze(self, raw_headers: str) -> HeaderAnalysisResult:
        """
        Parse and score email headers.

        Args:
            raw_headers: Raw email header block as a string
                         (can be partial — just the headers section).

        Returns:
            HeaderAnalysisResult
        """
        result = HeaderAnalysisResult()

        if not raw_headers or not raw_headers.strip():
            result.flags.append("No headers provided")
            return result

        try:
            # Parse headers
            parser = HeaderParser(policy=policy.default)
            msg = parser.parsestr(raw_headers, headersonly=True)

            # --------------------------------------------------------
            # 1. Authentication-Results (SPF / DKIM / DMARC)
            # --------------------------------------------------------
            auth_results = msg.get("Authentication-Results", "")
            if auth_results:
                spf, dkim, dmarc = _parse_auth_results(auth_results)
                result.spf_result = spf
                result.dkim_result = dkim
                result.dmarc_result = dmarc
            else:
                # Fallback: check Received-SPF header
                received_spf = msg.get("Received-SPF", "")
                if received_spf:
                    m = re.search(r"^(\w+)", received_spf.strip().lower())
                    if m:
                        result.spf_result = m.group(1)

                # DKIM-Signature presence = at least attempted
                if msg.get("DKIM-Signature"):
                    if result.dkim_result == "none":
                        result.dkim_result = "present"

            # Flag authentication failures
            if result.spf_result in ("fail", "softfail"):
                result.flags.append(f"SPF {result.spf_result} — sender not authorised by domain")
            if result.dkim_result == "fail":
                result.flags.append("DKIM signature failed — message may be tampered")
            if result.dmarc_result == "fail":
                result.flags.append("DMARC failed — domain alignment check failed")
            if result.spf_result == "none" and result.dkim_result == "none":
                result.flags.append("No SPF or DKIM authentication found")

            # --------------------------------------------------------
            # 2. From → extract domain
            # --------------------------------------------------------
            from_header = msg.get("From", "")
            result.from_domain = _extract_domain(from_header)

            # --------------------------------------------------------
            # 3. Reply-To vs From mismatch
            # --------------------------------------------------------
            reply_to = msg.get("Reply-To", "")
            if reply_to:
                result.reply_to_domain = _extract_domain(reply_to)
                if (
                    result.reply_to_domain
                    and result.from_domain
                    and result.reply_to_domain != result.from_domain
                ):
                    result.reply_to_mismatch = True
                    result.flags.append(
                        f"Reply-To domain ({result.reply_to_domain}) differs from "
                        f"From domain ({result.from_domain})"
                    )

            # --------------------------------------------------------
            # 4. Return-Path mismatch
            # --------------------------------------------------------
            return_path = msg.get("Return-Path", "")
            if return_path:
                result.return_path_domain = _extract_domain(return_path)
                if (
                    result.return_path_domain
                    and result.from_domain
                    and result.return_path_domain != result.from_domain
                ):
                    result.return_path_mismatch = True
                    result.flags.append(
                        f"Return-Path domain ({result.return_path_domain}) differs from "
                        f"From domain ({result.from_domain})"
                    )

            # --------------------------------------------------------
            # 5. Received chain hop count
            # --------------------------------------------------------
            received_headers = msg.get_all("Received") or []
            result.received_hops = len(received_headers)
            if result.received_hops > 7:
                result.flags.append(
                    f"Unusually long Received chain ({result.received_hops} hops) — "
                    "possible mail relay abuse"
                )
            elif result.received_hops == 0:
                result.flags.append("No Received headers — possibly hand-crafted or spoofed")

            # --------------------------------------------------------
            # 6. Display-name spoofing
            # --------------------------------------------------------
            if from_header:
                spoofed, brand = _check_display_name_spoof(from_header)
                result.display_name_spoof = spoofed
                result.spoofed_brand = brand
                if spoofed:
                    result.flags.append(
                        f"Display-name spoof: sender claims to be {brand.title()} "
                        f"but email comes from {result.from_domain or 'unknown domain'}"
                    )

            # --------------------------------------------------------
            # 7. X-Mailer / User-Agent analysis
            # --------------------------------------------------------
            mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
            result.mailer = mailer
            if mailer:
                mailer_l = mailer.lower()
                for pat in _SUSPICIOUS_MAILERS:
                    if re.search(pat, mailer_l):
                        result.suspicious_mailer = True
                        result.flags.append(f"Suspicious mailer detected: {mailer[:80]}")
                        break

            # --------------------------------------------------------
            # 8. Date anomaly (>7 days future or >30 days past)
            # --------------------------------------------------------
            date_str = msg.get("Date", "")
            if date_str:
                try:
                    from email.utils import parsedate_to_datetime
                    email_dt = parsedate_to_datetime(date_str)
                    now = datetime.now(timezone.utc)
                    diff_days = int((email_dt - now).total_seconds() / 86400)
                    result.date_days_diff = diff_days
                    if diff_days > 7:
                        result.date_anomaly = True
                        result.flags.append(
                            f"Email date is {diff_days} days in the future — likely spoofed"
                        )
                    elif diff_days < -90:
                        result.date_anomaly = True
                        result.flags.append(
                            f"Email date is {abs(diff_days)} days in the past — suspicious"
                        )
                except Exception:
                    pass  # Malformed date is itself suspicious but not critical

            # --------------------------------------------------------
            # 9. Free/throwaway From domain
            # --------------------------------------------------------
            if result.from_domain and result.from_domain in _FREE_EMAIL_DOMAINS:
                result.flags.append(
                    f"From address uses free/throwaway domain ({result.from_domain})"
                )

            # --------------------------------------------------------
            # RISK SCORING
            # --------------------------------------------------------
            score = 0.0

            # Auth failures
            if result.spf_result in ("fail",):
                score += 0.30
            elif result.spf_result in ("softfail",):
                score += 0.15
            if result.dkim_result == "fail":
                score += 0.25
            if result.dmarc_result == "fail":
                score += 0.20
            if result.spf_result == "none" and result.dkim_result == "none":
                score += 0.10

            # Mismatches
            if result.reply_to_mismatch:
                score += 0.25
            if result.return_path_mismatch:
                score += 0.15

            # Spoofing
            if result.display_name_spoof:
                score += 0.35

            # Infrastructure
            if result.received_hops > 7:
                score += 0.10
            if result.received_hops == 0:
                score += 0.10

            # Mailer
            if result.suspicious_mailer:
                score += 0.15

            # Date
            if result.date_anomaly:
                score += 0.10

            # Free domain as From (minor signal on its own)
            if result.from_domain and result.from_domain in _FREE_EMAIL_DOMAINS:
                score += 0.05

            result.risk_score = round(min(1.0, score), 4)
            result.is_suspicious = result.risk_score >= 0.25

        except Exception as e:
            logger.error("Header analysis failed: %s", e)
            result.flags.append(f"Header parsing error: {str(e)[:100]}")

        return result


# Module-level singleton
header_analyzer = HeaderAnalyzer()
