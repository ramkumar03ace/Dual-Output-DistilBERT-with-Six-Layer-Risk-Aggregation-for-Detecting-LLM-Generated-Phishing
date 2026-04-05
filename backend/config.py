"""
Configuration settings for the phishing detection backend.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # API Settings
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Phishing Detection API"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Model Settings
    HF_MODEL_ID: str = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
    MAX_TEXT_LENGTH: int = 512
    
    # Classification Thresholds
    HIGH_RISK_THRESHOLD: float = 0.85
    MEDIUM_RISK_THRESHOLD: float = 0.50
    
    # URL Analysis
    VIRUSTOTAL_API_KEY: str = ""  # Optional: set in .env for URL reputation checks
    
    # CORS Settings
    # Note: allow_origins=["*"] + allow_credentials=True is invalid per CORS spec.
    # Use explicit origins instead.
    CORS_ORIGINS: list = [
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "null",  # file:// origin for local HTML files
    ]
    CORS_ALLOW_CREDENTIALS: bool = False
    CORS_ALLOW_METHODS: list = ["GET", "POST", "OPTIONS"]
    CORS_ALLOW_HEADERS: list = ["Content-Type", "Authorization"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()
