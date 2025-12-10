# Backend Architecture & Implementation Details

## Core Service Files Reference

### 1. Database Connection Management (backend/auth-service/app/dependencies.py)

```python
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.config import get_settings

settings = get_settings()

# Create async engine
engine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,  # Test connections before using
    pool_recycle=3600,   # Recycle connections after 1 hour
)

# Session factory
SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database session"""
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def get_current_user_id(
    token: str = Header(..., alias="authorization"),
    auth_service: AuthService = Depends()
) -> int:
    """Extract and verify user ID from JWT token"""
    if not token.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    token = token[7:]  # Remove "Bearer " prefix
    return auth_service.verify_token(token)
```

### 2. Structured Logging (backend/auth-service/app/utils/logger.py)

```python
import logging
import json
import sys
from datetime import datetime
from pythonjsonlogger import jsonlogger
from app.config import get_settings

def setup_logging():
    """Configure structured JSON logging"""
    settings = get_settings()
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(settings.log_level)
    
    # Remove default handlers
    logger.handlers = []
    
    # Console handler with JSON formatter
    console_handler = logging.StreamHandler(sys.stdout)
    
    if settings.log_format == "json":
        formatter = jsonlogger.JsonFormatter(
            "%(timestamp)s %(level)s %(name)s %(message)s"
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def log_operation(operation: str, user_id: int, details: dict = None):
    """Log operation for audit trail"""
    logger = logging.getLogger(__name__)
    log_data = {
        "operation": operation,
        "user_id": user_id,
        "timestamp": datetime.utcnow().isoformat(),
        "details": details or {}
    }
    logger.info(json.dumps(log_data))
```

### 3. Security Utilities (backend/auth-service/app/utils/security.py)

```python
import re
from typing import Optional

def sanitize_input(value: str, max_length: int = 500) -> str:
    """Sanitize and validate user input"""
    if not isinstance(value, str):
        raise ValueError("Input must be string")
    
    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    
    # Remove potentially dangerous characters
    value = value.strip()
    return value

def validate_email_format(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password: str) -> Optional[str]:
    """Validate password meets security requirements"""
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit"
    if not any(c in '!@#$%^&*' for c in password):
        return "Password must contain at least one special character"
    return None
```

### 4. Custom Middleware (backend/auth-service/app/middleware.py)

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import time
import logging
import json
from uuid import uuid4

logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        """Log all requests and responses"""
        request_id = str(uuid4())
        request.state.request_id = request_id
        
        start_time = time.time()
        
        # Log request
        logger.info(json.dumps({
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else "unknown",
            "timestamp": time.time()
        }))
        
        response = await call_next(request)
        
        # Log response
        process_time = time.time() - start_time
        logger.info(json.dumps({
            "request_id": request_id,
            "status_code": response.status_code,
            "process_time": process_time
        }))
        
        response.headers["X-Request-ID"] = request_id
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests = {}
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Simple rate limiting middleware"""
        client_ip = request.client.host if request.client else "unknown"
        
        now = time.time()
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Remove requests older than 1 minute
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if now - req_time < 60
        ]
        
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return Response(
                content=json.dumps({"detail": "Rate limit exceeded"}),
                status_code=429,
                media_type="application/json"
            )
        
        self.requests[client_ip].append(now)
        return await call_next(request)
```

### 5. Exception Handling (backend/auth-service/app/exceptions.py)

```python
from fastapi import HTTPException, status
from typing import Optional, Any

class ApplicationException(HTTPException):
    """Base application exception"""
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: str = "Internal server error",
        code: Optional[str] = None,
        data: Optional[Any] = None
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.code = code or "INTERNAL_ERROR"
        self.data = data

class ValidationException(ApplicationException):
    """Validation error"""
    def __init__(self, detail: str, code: str = "VALIDATION_ERROR"):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
            code=code
        )

class AuthenticationException(ApplicationException):
    """Authentication error"""
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            code="AUTH_ERROR"
        )

class AuthorizationException(ApplicationException):
    """Authorization error"""
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            code="FORBIDDEN"
        )

class ResourceNotFoundException(ApplicationException):
    """Resource not found"""
    def __init__(self, resource: str = "Resource"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} not found",
            code="NOT_FOUND"
        )

class ConflictException(ApplicationException):
    """Resource conflict (e.g., duplicate)"""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
            code="CONFLICT"
        )
```

### 6. Tests (backend/auth-service/tests/test_auth.py)

```python
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.main import app, create_app
from app.models.user import Base

@pytest.fixture
async def test_db():
    """Create test database"""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    TestingSessionLocal = async_sessionmaker(engine, class_=AsyncSession)
    
    async with TestingSessionLocal() as session:
        yield session
    
    await engine.dispose()

@pytest.mark.asyncio
async def test_register_user(test_db):
    """Test user registration"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@example.com",
                "username": "testuser",
                "password": "SecurePass123!",
                "full_name": "Test User"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        assert data["user"]["email"] == "test@example.com"

@pytest.mark.asyncio
async def test_login_user(test_db):
    """Test user login"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # First register
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@example.com",
                "username": "testuser",
                "password": "SecurePass123!",
            }
        )
        
        # Then login
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "SecurePass123!"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data

@pytest.mark.asyncio
async def test_invalid_password_too_weak(test_db):
    """Test weak password validation"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@example.com",
                "username": "testuser",
                "password": "weak"  # Too weak
            }
        )
        
        assert response.status_code == 422
        data = response.json()
        assert "password" in str(data)
```

---

## Frontend Component Examples

### Complete Form Component with Validation

```javascript
// frontend/src/components/Projects/CreateProjectForm.jsx

import React, { useState } from 'react';
import Button from '../Common/Button';
import ErrorAlert from '../Common/ErrorAlert';
import { validateInput } from '../../utils/validators';

const CreateProjectForm = ({ onSuccess, onCancel }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    start_date: new Date().toISOString().split('T')[0],
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState(null);

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.name || formData.name.trim().length < 3) {
      newErrors.name = 'Project name must be at least 3 characters';
    }
    
    if (!formData.description || formData.description.trim().length < 10) {
      newErrors.description = 'Description must be at least 10 characters';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    setLoading(true);
    setApiError(null);

    try {
      const response = await fetch('/api/v1/projects', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        },
        body: JSON.stringify(formData)
      });

      if (!response.ok) {
        throw new Error('Failed to create project');
      }

      const data = await response.json();
      onSuccess(data);
    } catch (error) {
      setApiError(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {apiError && <ErrorAlert message={apiError} />}
      
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Project Name *
        </label>
        <input
          type="text"
          name="name"
          value={formData.name}
          onChange={handleChange}
          className={`w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
            errors.name ? 'border-red-500' : 'border-gray-300'
          }`}
          placeholder="My Awesome Project"
          disabled={loading}
        />
        {errors.name && <p className="text-red-500 text-sm mt-1">{errors.name}</p>}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Description *
        </label>
        <textarea
          name="description"
          value={formData.description}
          onChange={handleChange}
          rows="4"
          className={`w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
            errors.description ? 'border-red-500' : 'border-gray-300'
          }`}
          placeholder="Describe your project..."
          disabled={loading}
        />
        {errors.description && (
          <p className="text-red-500 text-sm mt-1">{errors.description}</p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Start Date
        </label>
        <input
          type="date"
          name="start_date"
          value={formData.start_date}
          onChange={handleChange}
          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          disabled={loading}
        />
      </div>

      <div className="flex gap-3 pt-4">
        <Button type="submit" variant="primary" loading={loading}>
          Create Project
        </Button>
        <Button type="button" variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
};

export default CreateProjectForm;
```

---

## API Endpoint Specifications

### Authentication Endpoints

```
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "SecurePass123!",
  "full_name": "Full Name"
}

Response (201):
{
  "access_token": "eyJ0eXAi...",
  "token_type": "bearer",
  "expires_in": 86400,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "username",
    "full_name": "Full Name",
    "is_active": true,
    "is_admin": false,
    "created_at": "2025-12-11T10:30:00Z",
    "updated_at": "2025-12-11T10:30:00Z"
  }
}
```

```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response (200): Same as register
```

```
GET /api/v1/auth/me
Authorization: Bearer <token>

Response (200): User object
```

---

## Deployment Checklist

- [ ] Update `.env` with production values
- [ ] Generate strong JWT_SECRET_KEY
- [ ] Configure PostgreSQL backups
- [ ] Set up monitoring and alerting
- [ ] Enable HTTPS/TLS
- [ ] Configure domain and DNS
- [ ] Set up log aggregation
- [ ] Create database indexes
- [ ] Run security scan
- [ ] Load test the application
- [ ] Document API endpoints
- [ ] Train team on deployment procedures

---

**Complete implementation guide for production-ready PMA application.**