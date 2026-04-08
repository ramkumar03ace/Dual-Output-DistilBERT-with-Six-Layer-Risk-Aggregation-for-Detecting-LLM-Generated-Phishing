"""
Pydantic schemas for API request/response models.
"""

from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class EmailRequest(BaseModel):
    """Request schema for email analysis."""
    
    text: str = Field(..., description="Email body text to analyze", min_length=1)
    subject: Optional[str] = Field(None, description="Optional email subject line")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "text": "Dear Customer, Your account has been compromised. Click here to verify.",
                    "subject": "Urgent: Account Security Alert"
                }
            ]
        }
    }


class EmailResponse(BaseModel):
    """Response schema for email analysis."""
    
    is_phishing: bool = Field(..., description="Whether the email is classified as phishing")
    confidence: float = Field(..., description="Model confidence score (0-1)", ge=0, le=1)
    label: str = Field(..., description="Classification label: PHISHING or LEGITIMATE")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, or HIGH")
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "is_phishing": True,
                    "confidence": 0.9981,
                    "label": "PHISHING",
                    "risk_level": "HIGH"
                }
            ]
        }
    }


class BatchEmailRequest(BaseModel):
    """Request schema for batch email analysis."""
    
    emails: List[EmailRequest] = Field(..., description="List of emails to analyze", min_length=1)


class BatchEmailResponse(BaseModel):
    """Response schema for batch email analysis."""
    
    results: List[EmailResponse] = Field(..., description="Analysis results for each email")
    total: int = Field(..., description="Total number of emails analyzed")
    phishing_count: int = Field(..., description="Number of emails classified as phishing")
    legitimate_count: int = Field(..., description="Number of emails classified as legitimate")


class HealthResponse(BaseModel):
    """Response schema for health check."""
    
    status: str = Field(..., description="Service status")
    model_loaded: bool = Field(..., description="Whether the ML model is loaded")
    version: str = Field(..., description="API version")


# --- URL Analysis Schemas ---

class URLAnalysisRequest(BaseModel):
    """Request schema for URL analysis."""
    url: str = Field(..., description="URL to analyze", min_length=1)

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class URLResult(BaseModel):
    """Result for a single URL analysis."""
    url: str = Field(..., description="The analyzed URL")
    domain: str = Field(..., description="Extracted domain")
    is_suspicious: bool = Field(..., description="Whether the URL is suspicious")
    risk_score: float = Field(..., description="Risk score (0-1)", ge=0, le=1)
    flags: List[str] = Field(default_factory=list, description="List of suspicious indicators")
    domain_age_days: Optional[int] = Field(None, description="Domain age in days")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    ssl_valid: Optional[bool] = Field(None, description="Whether SSL certificate is valid")
    ssl_issuer: Optional[str] = Field(None, description="SSL certificate issuer")
    vt_malicious: Optional[int] = Field(None, description="VirusTotal malicious count")


class URLAnalysisResponse(BaseModel):
    """Response for URL analysis."""
    results: List[URLResult] = Field(..., description="Analysis results per URL")
    total_urls: int = Field(..., description="Total URLs analyzed")
    suspicious_count: int = Field(..., description="Number of suspicious URLs")
    highest_risk: float = Field(..., description="Highest risk score found")


class FullAnalysisRequest(BaseModel):
    """Request schema for full email + URL analysis."""
    text: str = Field(..., description="Email body text", min_length=1)
    subject: Optional[str] = Field(None, description="Email subject line")


class FullAnalysisResponse(BaseModel):
    """Combined email text + URL analysis response."""
    # Text analysis
    text_analysis: EmailResponse = Field(..., description="ML text classification result")
    
    # URL analysis
    urls_found: int = Field(..., description="Number of URLs found in email")
    url_analysis: Optional[URLAnalysisResponse] = Field(None, description="URL analysis results")
    
    # Combined verdict
    overall_verdict: str = Field(..., description="SAFE, SUSPICIOUS, or PHISHING")
    overall_risk_score: float = Field(..., description="Combined risk score (0-1)")
    risk_factors: List[str] = Field(default_factory=list, description="Key risk factors")


# --- Deep Analysis Schemas (Web Crawler + Visual) ---

class CrawlResultSchema(BaseModel):
    """Crawl result for a single URL."""
    url: str = Field(..., description="Original URL")
    final_url: str = Field("", description="Final URL after redirects")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    page_title: str = Field("", description="Page title")
    was_redirected: bool = Field(False, description="Whether URL was redirected")
    redirect_chain: List[str] = Field(default_factory=list, description="Redirect chain")
    has_login_form: bool = Field(False, description="Whether page has login form")
    has_password_field: bool = Field(False, description="Whether page has password field")
    screenshot_path: Optional[str] = Field(None, description="Local path to screenshot file")
    screenshot_url: Optional[str] = Field(None, description="HTTP URL to fetch the screenshot image")
    error: Optional[str] = Field(None, description="Error if crawl failed")


class VisualAnalysisSchema(BaseModel):
    """Visual analysis of a crawled page."""
    is_fake_login: bool = Field(False, description="Whether page is a fake login")
    risk_score: float = Field(0.0, description="Visual risk score (0-1)")
    impersonated_brand: Optional[str] = Field(None, description="Brand being impersonated")
    flags: List[str] = Field(default_factory=list, description="Suspicious indicators")


class LinkCheckSchema(BaseModel):
    """Result of link checking."""
    total_links: int = Field(0, description="Total links found")
    checked_links: int = Field(0, description="Links checked")
    suspicious_links: int = Field(0, description="Suspicious links found")
    risk_score: float = Field(0.0, description="Link risk score (0-1)")
    flags: List[str] = Field(default_factory=list, description="Suspicious indicators")


class SenderInfo(BaseModel):
    """Email sender metadata from headers."""
    from_name: Optional[str] = Field(None, description="Sender display name")
    from_email: Optional[str] = Field(None, description="Sender email address")
    mailed_by: Optional[str] = Field(None, description="Mailed-by domain")
    signed_by: Optional[str] = Field(None, description="DKIM signed-by domain")
    security: Optional[str] = Field(None, description="Encryption/security info")


class SenderAnalysisSchema(BaseModel):
    """Result of sender metadata analysis."""
    is_suspicious: bool = Field(False, description="Whether sender looks suspicious")
    risk_score: float = Field(0.0, description="Sender risk score (0-1)")
    flags: List[str] = Field(default_factory=list, description="Suspicious indicators")


class AIAuthorshipSchema(BaseModel):
    """Result of AI-authorship detection."""
    is_ai_generated: bool = Field(False, description="Whether the text is likely AI-generated")
    ai_authorship_score: float = Field(0.0, description="AI authorship probability (0=human, 1=AI)", ge=0, le=1)
    signals: List[str] = Field(default_factory=list, description="Human-readable signals that triggered AI detection")
    burstiness_score: float = Field(0.0, description="Low burstiness = AI-like uniform sentence structure (0-1)", ge=0, le=1)
    perplexity_proxy: float = Field(0.0, description="Low entropy = predictable AI word choices (0-1)", ge=0, le=1)
    vocabulary_richness: float = Field(0.0, description="Low TTR = limited lexical diversity, AI-like (0-1)", ge=0, le=1)
    repetition_score: float = Field(0.0, description="High bigram repetition = AI-like (0-1)", ge=0, le=1)
    formality_score: float = Field(0.0, description="High formal/AI discourse marker density (0-1)", ge=0, le=1)


# --- Header Forensics Schema ---

class HeaderAnalysisSchema(BaseModel):
    """Result of email header forensics analysis (Layer 6)."""
    spf_result: str = Field("none", description="SPF check result: pass | fail | softfail | neutral | none")
    dkim_result: str = Field("none", description="DKIM check result: pass | fail | present | none")
    dmarc_result: str = Field("none", description="DMARC check result: pass | fail | none")
    reply_to_mismatch: bool = Field(False, description="Reply-To domain differs from From domain")
    from_domain: str = Field("", description="Sending domain extracted from From header")
    reply_to_domain: str = Field("", description="Domain from Reply-To header")
    return_path_domain: str = Field("", description="Domain from Return-Path header")
    return_path_mismatch: bool = Field(False, description="Return-Path domain differs from From domain")
    received_hops: int = Field(0, description="Number of Received headers (mail relay hops)")
    display_name_spoof: bool = Field(False, description="Display name claims known brand but domain doesn't match")
    spoofed_brand: str = Field("", description="Brand name being spoofed in display name")
    suspicious_mailer: bool = Field(False, description="X-Mailer matches known phishing toolkit patterns")
    mailer: str = Field("", description="X-Mailer / User-Agent header value")
    date_anomaly: bool = Field(False, description="Email date is suspiciously far in future or past")
    date_days_diff: int = Field(0, description="Days difference between email date and now")
    is_suspicious: bool = Field(False, description="Whether headers look suspicious overall")
    risk_score: float = Field(0.0, description="Header forensics risk score (0-1)", ge=0, le=1)
    flags: List[str] = Field(default_factory=list, description="Specific suspicious findings")


# --- XAI Schemas ---

class TokenAttributionSchema(BaseModel):
    """Attribution score for a single token."""
    token: str = Field(..., description="The word/token")
    score: float = Field(..., description="Attribution score (0-1, higher = more influential)", ge=0, le=1)
    is_highlighted: bool = Field(False, description="Whether this token should be visually highlighted")


class XAIExplanationSchema(BaseModel):
    """Explainable AI output — token attribution + human-readable risk explanation."""
    available: bool = Field(True, description="Whether XAI ran successfully")
    tokens: List[TokenAttributionSchema] = Field(default_factory=list, description="Token-level attribution scores")
    top_tokens: List[str] = Field(default_factory=list, description="Top influential tokens (sorted by score)")
    risk_categories: List[str] = Field(default_factory=list, description="Detected risk categories (urgency, credential_request, etc.)")
    explanation: str = Field("", description="Full human-readable explanation of the classification decision")
    summary: str = Field("", description="Short one-liner summary of why this was flagged")
    top_token_confidence_delta: float = Field(0.0, description="Confidence drop when top token is removed (LOO perturbation)")


# --- Adversarial Robustness Schemas ---

class AdversarialAttackResult(BaseModel):
    """Result for a single adversarial attack variant."""
    attack_type: str = Field(..., description="Attack category: homoglyph | zero_width | url_obfuscation | prompt_evasion")
    variant_name: str = Field(..., description="Human-readable description of the variant")
    original_score: float = Field(..., description="Classifier confidence on original text", ge=0, le=1)
    adversarial_score: float = Field(..., description="Classifier confidence on adversarial text", ge=0, le=1)
    score_delta: float = Field(..., description="adversarial_score − original_score")
    evasion_success: bool = Field(..., description="True if adversarial variant evaded all detection layers")
    detection_notes: List[str] = Field(default_factory=list, description="Heuristic/classifier findings for this variant")


class AdversarialAttackBreakdown(BaseModel):
    """Per-attack-type summary."""
    tested: int = Field(..., description="Number of variants tested for this attack type")
    evaded: int = Field(..., description="Number of variants that evaded detection")


class AdversarialRobustnessRequest(BaseModel):
    """Request for adversarial robustness testing."""
    text: str = Field(..., description="Email body text to test", min_length=10)
    subject: Optional[str] = Field(None, description="Optional email subject")


class AdversarialRobustnessResponse(BaseModel):
    """Full adversarial robustness report."""
    total_tests: int = Field(..., description="Total attack variants tested")
    evasion_successes: int = Field(..., description="Number of variants that fully evaded detection")
    evasion_rate: float = Field(..., description="Fraction of tests that evaded detection (0-1)", ge=0, le=1)
    resilience_score: float = Field(..., description="1 − evasion_rate; higher is better (0-1)", ge=0, le=1)
    summary: str = Field(..., description="Human-readable resilience summary")
    attack_breakdown: dict = Field(default_factory=dict, description="Per-attack-type {tested, evaded} counts")
    results: List[AdversarialAttackResult] = Field(default_factory=list, description="Per-variant results")


class DeepAnalysisRequest(BaseModel):
    """Request for deep analysis (text + URL + crawl + visual + sender + headers)."""
    text: str = Field(..., description="Email body text", min_length=1)
    email_html: Optional[str] = Field(None, description="Raw HTML of email (for extracting links from images, buttons, etc.)")
    subject: Optional[str] = Field(None, description="Email subject line")
    raw_headers: Optional[str] = Field(None, description="Raw email headers block for forensic analysis (Layer 6)")
    crawl_urls: bool = Field(True, description="Whether to crawl URLs with browser")
    take_screenshots: bool = Field(True, description="Whether to capture screenshots")
    sender_info: Optional[SenderInfo] = Field(None, description="Email sender metadata from headers")


class DeepAnalysisResponse(BaseModel):
    """Full deep analysis combining all detection layers."""
    # Layer 1: Text classification
    text_analysis: EmailResponse = Field(..., description="ML classification")
    
    # Layer 2: URL static analysis
    urls_found: int = Field(0, description="URLs found in email")
    urls_list: List[str] = Field(default_factory=list, description="List of URLs found")
    url_analysis: Optional[URLAnalysisResponse] = Field(None, description="URL analysis")
    
    # Layer 3: Web crawling
    crawl_results: List[CrawlResultSchema] = Field(default_factory=list, description="Crawl results")
    
    # Layer 4: Visual analysis
    visual_analysis: List[VisualAnalysisSchema] = Field(default_factory=list, description="Visual analysis")
    
    # Layer 5: Link checking
    link_analysis: Optional[LinkCheckSchema] = Field(None, description="Link checking")
    
    # Sender analysis
    sender_analysis: Optional[SenderAnalysisSchema] = Field(None, description="Sender metadata analysis")

    # Layer 6: Header forensics
    header_analysis: Optional[HeaderAnalysisSchema] = Field(None, description="Email header forensics (SPF/DKIM/DMARC/Reply-To/Received chain)")

    # AI authorship detection (dual classifier output)
    ai_authorship: Optional[AIAuthorshipSchema] = Field(None, description="AI-generated text detection result")

    # XAI — token attribution + human-readable explanation
    xai_explanation: Optional[XAIExplanationSchema] = Field(None, description="Explainable AI token attribution and risk explanation")

    # Combined verdict
    overall_verdict: str = Field(..., description="SAFE, SUSPICIOUS, or PHISHING")
    overall_risk_score: float = Field(..., description="Combined risk score (0-1)")
    is_ai_generated: bool = Field(False, description="Whether email text is likely AI-generated")
    ai_authorship_score: float = Field(0.0, description="AI authorship probability (0=human, 1=AI)", ge=0, le=1)
    risk_factors: List[str] = Field(default_factory=list, description="Key risk factors")
    analysis_layers: List[str] = Field(default_factory=list, description="Layers that ran")

