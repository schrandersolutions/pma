# PMA Application - Migration & Implementation Roadmap

## 📌 Quick Start (5 Minutes)

### Phase 1: Project Setup

```bash
# 1. Clone and setup repository structure
git clone https://github.com/ashu-duppati12/pma.git
cd pma

# 2. Create backend structure
mkdir -p backend/{auth-service,pm-service,reporting-service,api-gateway}/app
mkdir -p backend/auth-service/app/{schemas,models,repositories,services,api/v1,utils}
mkdir -p backend/auth-service/{tests,migrations}

# 3. Create frontend structure  
mkdir -p frontend/src/{components,pages,hooks,context,api,utils,styles}

# 4. Copy configuration files
cp .env.example .env
# Edit .env with your values
```

### Phase 2: Database Migration (10 Minutes)

```bash
# 1. Install Alembic for migrations
cd backend/auth-service
pip install alembic

# 2. Initialize migrations
alembic init migrations

# 3. Update migrations/env.py with your database URL
# 4. Auto-generate migration
alembic revision --autogenerate -m "Initial schema"

# 5. Apply migration
alembic upgrade head
```

### Phase 3: Backend Services (30 Minutes)

```bash
# 1. Install dependencies
cd backend/auth-service
pip install -r requirements.txt

# 2. Run FastAPI server with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 5001

# 3. Access API documentation
# Navigate to http://localhost:5001/api/docs
```

### Phase 4: Frontend Setup (20 Minutes)

```bash
# 1. Setup React with Vite
cd frontend
npm create vite@latest . -- --template react

# 2. Install dependencies
npm install axios react-router-dom tailwindcss

# 3. Start development server
npm run dev

# 4. Access frontend
# Navigate to http://localhost:5173
```

---

## 🔄 Migration Path from Old to New

### Step 1: Database Schema Updates

**Old Flask Models → New SQLAlchemy Async Models**

```python
# OLD (Flask-SQLAlchemy)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Direct model usage

# NEW (SQLAlchemy 2.0 Async)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    # Async-first, proper indexing
```

**Data Migration Script**

```python
# backend/migrate_data.py
import asyncio
from sqlalchemy import text
from app.dependencies import engine, SessionLocal

async def migrate_users():
    """Migrate users from old to new schema"""
    async with SessionLocal() as session:
        # Copy data from old schema
        result = await session.execute(
            text("SELECT id, email, password_hash FROM users_old")
        )
        old_users = result.fetchall()
        
        # Insert into new schema
        for old_user in old_users:
            new_user = User(
                id=old_user.id,
                email=old_user.email,
                password_hash=old_user.password_hash,
            )
            session.add(new_user)
        
        await session.commit()

if __name__ == "__main__":
    asyncio.run(migrate_users())
```

### Step 2: API Endpoints Update

**Old Flask Routes → New FastAPI Routers**

```python
# OLD (Flask)
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    # Manual validation
    # Direct database access
    return jsonify(response)

# NEW (FastAPI)
@router.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    session: AsyncSession = Depends(get_session),
    auth_service: AuthService = Depends()
):
    """Automatic validation, async, dependency injection"""
    return await auth_service.login(credentials, session)
```

### Step 3: Frontend Refactoring

**Old Class Components → New Functional Components with Hooks**

```javascript
// OLD (Class Component)
class LoginForm extends React.Component {
  state = { email: '', password: '' };
  
  handleLogin = async () => {
    const response = await axios.post('/api/auth/login', this.state);
    this.setState({ token: response.data.token });
  };
  
  render() {
    return <form onSubmit={this.handleLogin}>...</form>;
  }
}

// NEW (Functional Component with Hooks)
const LoginForm = () => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const { login } = useAuth();
  
  const handleLogin = async (e) => {
    e.preventDefault();
    await login(formData.email, formData.password);
  };
  
  return <form onSubmit={handleLogin}>...</form>;
};
```

---

## 🧪 Testing Strategy

### Backend Unit Tests

```bash
# Run tests with coverage
pytest --cov=app backend/auth-service/tests/

# Run specific test file
pytest backend/auth-service/tests/test_auth.py -v

# Run with markers
pytest -m "unit" backend/auth-service/tests/
```

### Frontend Unit Tests

```bash
# Setup Jest and React Testing Library
npm install --save-dev @testing-library/react @testing-library/jest-dom jest

# Run tests
npm run test

# Run with coverage
npm run test:coverage
```

### Integration Tests

```bash
# Start services
docker-compose up -d

# Run integration tests
pytest backend/auth-service/tests/integration/

# Run e2e tests
npm run test:e2e
```

---

## 📊 Performance Optimization Guide

### Backend Optimizations

```python
# 1. Database Query Optimization
# Use select() for specific columns instead of loading entire models
stmt = select(User.id, User.email).where(User.is_active == True)
result = await session.execute(stmt)

# 2. Connection Pooling
engine = create_async_engine(
    database_url,
    pool_size=10,          # Number of connections to pool
    max_overflow=20,       # Extra connections when pool is exhausted
    pool_pre_ping=True,    # Test connections before using
    pool_recycle=3600,     # Recycle after 1 hour
)

# 3. Caching
from functools import lru_cache

@lru_cache(maxsize=128)
def get_user_by_id(user_id: int):
    # Expensive operation cached
    return db.query(User).get(user_id)

# 4. Pagination
from sqlalchemy import limit, offset

stmt = (
    select(Project)
    .where(Project.owner_id == user_id)
    .limit(20)
    .offset(0)
)
```

### Frontend Optimizations

```javascript
// 1. Code Splitting
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Projects = React.lazy(() => import('./pages/ProjectsPage'));

// 2. Memoization
const ProjectList = React.memo(({ projects }) => {
  return projects.map(p => <ProjectItem key={p.id} project={p} />);
});

// 3. Image Optimization
import { Image } from './components/OptimizedImage';
<Image src="large.jpg" width={400} height={300} loading="lazy" />

// 4. Virtual Scrolling for large lists
import { FixedSizeList } from 'react-window';
<FixedSizeList height={600} itemCount={1000} itemSize={50}>
  {({ index, style }) => <ProjectItem style={style} />}
</FixedSizeList>
```

---

## 🔐 Security Checklist

### Backend Security

- [ ] **Input Validation**: All inputs validated with Pydantic
- [ ] **Password Hashing**: bcrypt with 12+ rounds
- [ ] **JWT Tokens**: HS256 with strong secret key (32+ chars)
- [ ] **HTTPS**: Force HTTPS in production
- [ ] **CORS**: Restricted to specific origins
- [ ] **SQL Injection**: Using parameterized queries (SQLAlchemy)
- [ ] **Rate Limiting**: Implemented per IP/user
- [ ] **Secrets Management**: Use environment variables, never hardcode
- [ ] **Dependency Audit**: `pip audit` or similar tools
- [ ] **Database Backups**: Automated daily backups

### Frontend Security

- [ ] **XSS Prevention**: React escapes by default, sanitize user content
- [ ] **CSRF Protection**: Include CSRF token in forms
- [ ] **Content Security Policy**: Implement strict CSP headers
- [ ] **Secure Storage**: Don't store passwords, use secure tokens
- [ ] **HTTPS Only**: Enforce HTTPS for all requests
- [ ] **Dependency Audit**: `npm audit` regularly
- [ ] **Input Validation**: Client + server validation
- [ ] **Error Handling**: Don't expose sensitive info in error messages

### DevOps Security

- [ ] **Secrets**: Never commit to git, use GitHub secrets
- [ ] **Container Security**: Non-root users, read-only filesystems
- [ ] **Network Policies**: Restrict service-to-service communication
- [ ] **Monitoring**: Log all access attempts and errors
- [ ] **Regular Updates**: Keep dependencies up to date
- [ ] **Vulnerability Scanning**: Use tools like Snyk, Dependabot

---

## 📈 Monitoring & Observability

### Logging Setup

```python
# Structured JSON logging for log aggregation
import logging
from pythonjsonlogger import jsonlogger

logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)
logger.addHandler(handler)

# Usage
logger.info("User login", extra={
    "user_id": 123,
    "ip": "192.168.1.1",
    "timestamp": datetime.utcnow().isoformat()
})
```

### Health Checks

```python
@app.get("/health")
async def health_check():
    """Kubernetes-compatible health check"""
    try:
        # Check database
        async with SessionLocal() as session:
            await session.execute(select(1))
        
        return {
            "status": "healthy",
            "service": "auth-service",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }, 503
```

### Metrics Collection

```python
# Using Prometheus for metrics
from prometheus_client import Counter, Histogram, Gauge

request_count = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

active_users = Gauge(
    'active_users',
    'Number of active users'
)
```

---

## 📅 Deployment Timeline (Example)

### Week 1: Setup & Development
- [ ] Day 1-2: Infrastructure setup, CI/CD pipeline
- [ ] Day 3-4: Backend services implementation
- [ ] Day 5: Initial testing and bug fixes

### Week 2: Frontend & Integration
- [ ] Day 1-3: Frontend implementation
- [ ] Day 4: Integration testing
- [ ] Day 5: Security audit

### Week 3: Testing & Documentation
- [ ] Day 1-2: Load testing, performance optimization
- [ ] Day 3-4: Documentation, runbooks
- [ ] Day 5: Team training, dry run

### Week 4: Production Deployment
- [ ] Day 1-2: Blue-green deployment setup
- [ ] Day 3-4: Canary deployment
- [ ] Day 5: Full production release, monitoring

---

## 🛠️ Troubleshooting Guide

### Common Backend Issues

**Issue**: Database connection timeout
```python
# Solution: Check connection string and pool configuration
SQLALCHEMY_POOL_SIZE=10
SQLALCHEMY_POOL_RECYCLE=3600
SQLALCHEMY_ECHO=True  # Debug SQL queries
```

**Issue**: JWT token verification failing
```python
# Solution: Ensure same secret key in all services
# Check token expiration: exp claim
import jwt
decoded = jwt.decode(token, secret, algorithms=["HS256"])
print(decoded)  # Check exp field
```

**Issue**: Slow database queries
```python
# Solution: Add indexes and optimize queries
# Check query performance
async with engine.begin() as conn:
    result = await conn.execute(
        text("EXPLAIN ANALYZE SELECT * FROM users WHERE email = :email"),
        {"email": "user@example.com"}
    )
```

### Common Frontend Issues

**Issue**: CORS errors
```javascript
// Solution: Check API gateway CORS configuration
// Ensure credentials included in requests
const client = axios.create({
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json'
  }
});
```

**Issue**: Token expired mid-session
```javascript
// Solution: Implement token refresh
client.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      // Try refreshing token
      return refreshToken().then(newToken => {
        // Retry request with new token
      });
    }
    return Promise.reject(error);
  }
);
```

---

## 📚 Additional Resources

### Documentation to Generate

1. **API Documentation** (`docs/API.md`)
   - All endpoints with examples
   - Request/response schemas
   - Error codes and meanings

2. **Architecture Decision Records** (`docs/ADR.md`)
   - Why FastAPI instead of Flask
   - Why PostgreSQL instead of MongoDB
   - Technology choices documented

3. **Operations Runbook** (`docs/RUNBOOK.md`)
   - Common operational tasks
   - How to scale services
   - How to handle incidents

4. **Development Guide** (`docs/DEVELOPMENT.md`)
   - How to set up local environment
   - Testing procedures
   - Code style guidelines

---

## ✅ Pre-Production Checklist

- [ ] All tests passing (unit, integration, e2e)
- [ ] Code coverage > 80%
- [ ] Security scan passed
- [ ] Performance test results acceptable
- [ ] Documentation complete
- [ ] Team training completed
- [ ] Incident response plan documented
- [ ] Backup and recovery tested
- [ ] Monitoring and alerting configured
- [ ] Rollback procedure documented

---

**This roadmap provides a complete path from current state to production-ready application.**