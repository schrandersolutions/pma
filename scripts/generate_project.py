# PMA PROJECT - COMPLETE SOURCE CODE GENERATOR (WINDOWS COMPATIBLE)
# Fixed version for Windows environments

"""
INSTRUCTIONS:
1. Save this file as: generate_project.py
2. Create a directory: mkdir pma && cd pma
3. Run: python generate_project.py
4. All source files will be created with proper structure
"""

import os
from pathlib import Path

# ============================================================================
# BACKEND - AUTH SERVICE - CONFIG
# ============================================================================

AUTH_CONFIG = '''# File: backend/auth-service/app/config.py
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
'''

AUTH_EXCEPTIONS = '''# File: backend/auth-service/app/exceptions.py
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
'''

AUTH_SECURITY = '''# File: backend/auth-service/app/utils/security.py
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from app.config import settings
from app.exceptions import AuthenticationException

class SecurityUtils:
    """Utility class for security operations"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    
    @staticmethod
    def create_access_token(data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(hours=settings.jwt_expiration_hours)
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    
    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """Decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationException("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationException("Invalid token")
'''

AUTH_SCHEMAS = '''# File: backend/auth-service/app/schemas/user.py
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional

class UserCreate(BaseModel):
    """User creation schema"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    full_name: Optional[str] = Field(default=None, max_length=100)

class UserLogin(BaseModel):
    """User login schema"""
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    """User response schema"""
    id: int
    email: str
    username: str
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    """Token response schema"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
'''

AUTH_MODELS = '''# File: backend/auth-service/app/models/user.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Index
from sqlalchemy.sql import func
from app.models.base import Base

class User(Base):
    """User model"""
    __tablename__ = "users"
    __table_args__ = (
        Index("idx_user_email", "email", unique=True),
        Index("idx_user_username", "username", unique=True),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
'''

BACKEND_REQUIREMENTS = '''# File: backend/auth-service/requirements.txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.6.0
pydantic-settings==2.1.0
sqlalchemy==2.0.27
alembic==1.13.1
asyncpg==0.29.0
psycopg2-binary==2.9.9
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
bcrypt==4.1.1
python-multipart==0.0.6
PyJWT==2.8.1
pytest==7.4.4
pytest-asyncio==0.23.2
httpx==0.25.2
pytest-cov==4.1.0
python-json-logger==2.0.7
black==23.12.0
isort==5.13.2
flake8==6.1.0
mypy==1.8.0
python-dotenv==1.0.0
email-validator==2.1.0
'''

BACKEND_DOCKERFILE = '''# File: backend/auth-service/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \\
    gcc \\
    postgresql-client \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \\
    CMD python -c "import requests; requests.get('http://localhost:5001/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001"]
'''

FRONTEND_PACKAGE = '''{
  "name": "pma-frontend",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext js,jsx",
    "test": "vitest",
    "format": "prettier --write src/**/*.{js,jsx,json,css}"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.0",
    "vite": "^5.0.0",
    "@testing-library/react": "^14.1.0",
    "vitest": "^1.1.0"
  }
}
'''

FRONTEND_VITE = '''// File: frontend/vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0'
  },
  build: {
    target: 'esnext',
    minify: 'terser'
  }
})
'''

FRONTEND_APP = '''// File: frontend/src/App.jsx
import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<h1>Login Page</h1>} />
          <Route path="/" element={<h1>Dashboard</h1>} />
        </Routes>
      </AuthProvider>
    </Router>
  )
}

export default App
'''

FRONTEND_AUTH_CONTEXT = '''// File: frontend/src/context/AuthContext.jsx
import React, { createContext } from 'react'

export const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  return (
    <AuthContext.Provider value={{ isAuthenticated: false }}>
      {children}
    </AuthContext.Provider>
  )
}
'''

DOCKER_COMPOSE = '''# File: docker-compose.yml
version: '3.9'

services:
  postgres:
    image: postgres:16-alpine
    container_name: pma-postgres
    environment:
      POSTGRES_DB: pma
      POSTGRES_USER: pmauser
      POSTGRES_PASSWORD: SecurePassword123!
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pmauser -d pma"]
      interval: 10s
      timeout: 5s
      retries: 5

  auth-service:
    build:
      context: ./backend/auth-service
      dockerfile: Dockerfile
    container_name: pma-auth-service
    environment:
      DATABASE_URL: postgresql+asyncpg://pmauser:SecurePassword123!@postgres:5432/pma
      DEBUG: "false"
    ports:
      - "5001:5001"
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./backend/auth-service:/app

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: pma-frontend
    ports:
      - "3000:3000"
    environment:
      VITE_API_URL: http://localhost:8000
    volumes:
      - ./frontend/src:/app/src

volumes:
  postgres_data:
'''

ENV_EXAMPLE = '''# File: .env.example
DEBUG=false
ENVIRONMENT=development
POSTGRES_DB=pma
POSTGRES_USER=pmauser
POSTGRES_PASSWORD=SecurePassword123!
DATABASE_URL=postgresql+asyncpg://pmauser:SecurePassword123!@postgres:5432/pma
JWT_SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
BCRYPT_ROUNDS=12
LOG_LEVEL=INFO
LOG_FORMAT=json
RATE_LIMIT_ENABLED=true
VITE_API_URL=http://localhost:8000
'''

# ============================================================================
# GENERATE FILES - FIXED FOR WINDOWS
# ============================================================================

def safe_create_file(filepath, content):
    """Safely create file with proper path handling for Windows"""
    try:
        # Convert to Path object for cross-platform compatibility
        p = Path(filepath)
        
        # Create parent directories
        p.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file
        p.write_text(content, encoding='utf-8')
        return True
    except Exception as e:
        print(f"❌ Error creating {filepath}: {str(e)}")
        return False

def generate_files():
    """Generate all project files with Windows compatibility"""
    
    files = {
        'backend/auth-service/app/__init__.py': '',
        'backend/auth-service/app/config.py': AUTH_CONFIG,
        'backend/auth-service/app/exceptions.py': AUTH_EXCEPTIONS,
        'backend/auth-service/app/utils/__init__.py': '',
        'backend/auth-service/app/utils/security.py': AUTH_SECURITY,
        'backend/auth-service/app/schemas/__init__.py': '',
        'backend/auth-service/app/schemas/user.py': AUTH_SCHEMAS,
        'backend/auth-service/app/schemas/token.py': '# Token schemas',
        'backend/auth-service/app/models/__init__.py': '',
        'backend/auth-service/app/models/base.py': 'from sqlalchemy.orm import declarative_base\\nBase = declarative_base()',
        'backend/auth-service/app/models/user.py': AUTH_MODELS,
        'backend/auth-service/app/services/__init__.py': '',
        'backend/auth-service/app/repositories/__init__.py': '',
        'backend/auth-service/app/api/__init__.py': '',
        'backend/auth-service/app/api/v1/__init__.py': '',
        'backend/auth-service/app/api/v1/auth.py': '# Auth routes',
        'backend/auth-service/requirements.txt': BACKEND_REQUIREMENTS,
        'backend/auth-service/Dockerfile': BACKEND_DOCKERFILE,
        'backend/auth-service/.env.example': ENV_EXAMPLE,
        'backend/pm-service/__init__.py': '',
        'frontend/package.json': FRONTEND_PACKAGE,
        'frontend/vite.config.js': FRONTEND_VITE,
        'frontend/Dockerfile': 'FROM node:18-alpine\\nWORKDIR /app\\nCOPY package.json .\\nRUN npm install\\nCOPY . .\\nRUN npm run build\\nEXPOSE 3000\\nCMD ["npm", "run", "dev"]',
        'frontend/.env.example': 'VITE_API_URL=http://localhost:8000',
        'frontend/src/__init__.js': '',
        'frontend/src/App.jsx': FRONTEND_APP,
        'frontend/src/index.jsx': 'import App from "./App"',
        'frontend/src/context/AuthContext.jsx': FRONTEND_AUTH_CONTEXT,
        'frontend/public/index.html': '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>PMA</title></head><body><div id="root"></div></body></html>',
        'docker-compose.yml': DOCKER_COMPOSE,
        '.env.example': ENV_EXAMPLE,
        '.gitignore': '__pycache__/\\n*.py[cod]\\nnode_modules/\\ndist/\\n.env\\n.vscode/\\n.idea/',
    }
    
    created_count = 0
    failed_count = 0
    
    for filepath, content in files.items():
        if safe_create_file(filepath, content):
            created_count += 1
            print(f"✓ Created: {filepath}")
        else:
            failed_count += 1
    
    return created_count, failed_count

if __name__ == "__main__":
    print("=" * 80)
    print("PMA PROJECT GENERATOR - WINDOWS COMPATIBLE")
    print("=" * 80)
    print()
    
    created, failed = generate_files()
    
    print()
    print("=" * 80)
    print(f"✅ Created: {created} files")
    if failed > 0:
        print(f"❌ Failed: {failed} files")
    print("=" * 80)
    print()
    
    if failed == 0:
        print("Next steps:")
        print("1. cd pma")
        print("2. cp .env.example .env")
        print("3. docker-compose up -d")
        print("4. Access at http://localhost:3000")
    else:
        print("Some files failed to create. Check the errors above.")
