# File: backend/auth-service/app/config.py
import os
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    """Application settings from environment variables"""
    
    # Application
    app_name: str = "PMA Auth Service"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False, validation_alias="DEBUG")
    environment: str = Field(default="development", validation_alias="ENVIRONMENT")
    
    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://pmauser:password@postgres:5432/pma",
        validation_alias="DATABASE_URL"
    )
    database_echo: bool = Field(default=False, validation_alias="SQLALCHEMY_ECHO")
    
    # JWT
    jwt_secret_key: str = Field(
        default="your-secret-key-change-this-in-production",
        validation_alias="JWT_SECRET_KEY"
    )
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(default=24, validation_alias="JWT_EXPIRATION_HOURS")
    
    # Security
    bcrypt_rounds: int = Field(default=12, validation_alias="BCRYPT_ROUNDS")
    
    # CORS
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        validation_alias="CORS_ORIGINS"
    )
    
    # Logging
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    log_format: str = Field(default="json", validation_alias="LOG_FORMAT")
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, validation_alias="RATE_LIMIT_ENABLED")
    rate_limit_requests: int = Field(default=100, validation_alias="RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(default=60, validation_alias="RATE_LIMIT_PERIOD")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()
