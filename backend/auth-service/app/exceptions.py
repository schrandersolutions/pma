# File: backend/auth-service/app/exceptions.py
from fastapi import status
from typing import Optional, Any, Dict

class ApplicationException(Exception):
    """Base application exception"""
    
    def __init__(
        self,
        error_code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        detail: Optional[Dict[str, Any]] = None
    ):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}
        super().__init__(self.message)

class ValidationException(ApplicationException):
    """Raised when input validation fails"""
    def __init__(self, message: str, detail: Optional[Dict] = None):
        super().__init__(
            error_code="VALIDATION_ERROR",
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )

class AuthenticationException(ApplicationException):
    """Raised when authentication fails"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            error_code="AUTHENTICATION_FAILED",
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED
        )

class AuthorizationException(ApplicationException):
    """Raised when user lacks permissions"""
    def __init__(self, message: str = "Access denied"):
        super().__init__(
            error_code="AUTHORIZATION_FAILED",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN
        )

class NotFoundException(ApplicationException):
    """Raised when resource is not found"""
    def __init__(self, message: str = "Resource not found"):
        super().__init__(
            error_code="NOT_FOUND",
            message=message,
            status_code=status.HTTP_404_NOT_FOUND
        )

class ConflictException(ApplicationException):
    """Raised when resource already exists"""
    def __init__(self, message: str = "Resource already exists"):
        super().__init__(
            error_code="CONFLICT",
            message=message,
            status_code=status.HTTP_409_CONFLICT
        )

class RateLimitException(ApplicationException):
    """Raised when rate limit exceeded"""
    def __init__(self):
        super().__init__(
            error_code="RATE_LIMIT_EXCEEDED",
            message="Too many requests",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS
        )
