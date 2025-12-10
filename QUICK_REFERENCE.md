# PMA Rewrite - Quick Reference Card

## 🚀 Start Here

### 1. Read Documentation (30 minutes)
- [ ] Read EXECUTIVE_SUMMARY.md (overview of changes)
- [ ] Read PMA_Rewrite_Guide.md (detailed implementation)
- [ ] Read Backend_Implementation.md (code examples)
- [ ] Read Migration_Roadmap.md (step-by-step process)

### 2. Local Setup (15 minutes)
```bash
git clone https://github.com/ashu-duppati12/pma.git
cd pma
cp .env.example .env
docker-compose up -d
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/api/docs
```

### 3. Test It Works (5 minutes)
```bash
# Test backend health
curl http://localhost:8000/health

# Test frontend loads
open http://localhost:3000

# View API documentation
open http://localhost:8000/api/docs
```

---

## 📋 Architecture Overview

```
┌─────────────────────────────────────────────┐
│           React Frontend (3000)              │
│  ├─ Hooks & Context API for state           │
│  ├─ Tailwind CSS for styling                │
│  └─ Protected routes with auth guard        │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│      API Gateway (8000) - FastAPI           │
│  ├─ Request routing & JWT validation        │
│  ├─ CORS handling                           │
│  └─ Rate limiting                           │
└──────────────┬──────────────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐┌────────┐┌──────────────┐
│  Auth  ││   PM   ││  Reporting   │
│(5001) ││(5002)  ││   (5003)     │
└────┬───┘└────┬───┘└──────┬───────┘
     └─────────┼───────────┘
              ▼
        ┌────────────┐
        │ PostgreSQL │
        │  Database  │
        └────────────┘
```

---

## 🔑 Key Technologies

### Backend Stack
- **Framework**: FastAPI (async web framework)
- **ORM**: SQLAlchemy 2.0 (with async support)
- **Validation**: Pydantic V2 (automatic validation)
- **Database**: PostgreSQL 16 (with connection pooling)
- **Auth**: JWT + bcrypt (secure authentication)
- **Testing**: pytest (comprehensive testing framework)
- **Server**: Uvicorn (ASGI application server)

### Frontend Stack
- **Framework**: React 18 (functional components)
- **State**: Context API + Custom Hooks
- **HTTP**: Axios (with interceptors)
- **Styling**: Tailwind CSS (utility-first)
- **Routing**: React Router v6 (with protected routes)
- **Build**: Vite (ultra-fast build tool)
- **Testing**: Jest + React Testing Library

### DevOps
- **Containerization**: Docker (multi-stage builds)
- **Orchestration**: Docker Compose (local) / Kubernetes (prod)
- **CI/CD**: GitHub Actions (automated workflows)
- **Cloud**: Azure Container Apps (recommended)
- **Monitoring**: Prometheus + JSON logging

---

## 📝 Common Commands

### Backend Development
```bash
# Start development server with auto-reload
cd backend/auth-service
uvicorn app.main:app --reload

# Run tests with coverage
pytest --cov=app tests/

# Format code
black app/
isort app/

# Type checking
mypy app/
```

### Frontend Development
```bash
# Start development server
cd frontend
npm run dev

# Run tests
npm test

# Build for production
npm run build

# Format code
npm run lint
npm run format
```

### Docker Operations
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f [service_name]

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up -d --build
```

### Database Operations
```bash
# Connect to PostgreSQL
psql postgresql://pmauser:password@localhost:5432/pma

# Create migration
alembic revision --autogenerate -m "description"

# Apply migration
alembic upgrade head

# Rollback migration
alembic downgrade -1

# View migration status
alembic current
```

---

## 🔒 Authentication Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │
       │ 1. POST /auth/register
       ▼
┌─────────────────────────────────┐
│      API Gateway (FastAPI)      │
└────────────┬────────────────────┘
             │
             │ 2. Validate Input (Pydantic)
             │
             ▼
┌─────────────────────────────────┐
│      Auth Service (5001)        │
│  ├─ Hash password (bcrypt)      │
│  ├─ Store in database           │
│  └─ Generate JWT token          │
└────────────┬────────────────────┘
             │
             │ 3. Return { token, user }
             │
             ▼
┌─────────────┐
│   Browser   │ 4. Store token in localStorage
│  (React App)│ 5. Add to Authorization header
└──────┬──────┘
       │
       │ 6. GET /api/projects (+ token)
       ▼
┌─────────────────────────────────┐
│      API Gateway (FastAPI)      │
│  ├─ Extract JWT token           │
│  ├─ Verify signature            │
│  └─ Extract user_id             │
└────────────┬────────────────────┘
             │
             │ 7. Forward to appropriate service
             │
             ▼
┌─────────────────────────────────┐
│      PM Service (5002)          │
│  ├─ Use user_id from context    │
│  └─ Return user's projects      │
└─────────────────────────────────┘
```

---

## 🧪 Testing Checklist

### Backend Tests
- [ ] User registration with valid data
- [ ] User registration with invalid email
- [ ] User registration with weak password
- [ ] User login with correct credentials
- [ ] User login with wrong password
- [ ] JWT token validation
- [ ] Token expiration
- [ ] Rate limiting

### Frontend Tests
- [ ] LoginForm renders correctly
- [ ] Form validation shows errors
- [ ] Login success redirects to dashboard
- [ ] Login failure shows error message
- [ ] Protected route redirects unauthenticated
- [ ] Project list loads and displays data
- [ ] Create project form submits correctly
- [ ] Logout clears token

### Integration Tests
- [ ] User can register → login → create project
- [ ] Project can be shared with other user
- [ ] Task can be assigned to team member
- [ ] Reports can be generated for project
- [ ] User can update own profile

---

## 🐛 Debugging Tips

### FastAPI Debugging
```python
# Enable SQL query logging
SQLALCHEMY_ECHO=True

# Check JWT token contents
import jwt
decoded = jwt.decode(token, settings.jwt_secret_key, 
                    algorithms=["HS256"])
print(decoded)

# Test endpoint with curl
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass"}'
```

### React Debugging
```javascript
// Log component lifecycle
console.log('Component mounted');

// Check context values
console.log('Auth context:', useAuth());

// Verify API calls
console.log('API response:', response.data);

// Monitor state changes
console.log('State updated:', newState);
```

### Docker Debugging
```bash
# View container logs
docker logs -f pma-auth-service

# Execute command in container
docker exec -it pma-auth-service bash

# Check resource usage
docker stats pma-auth-service

# Inspect container network
docker inspect pma-postgres
```

---

## 📊 Performance Optimization Checklist

### Backend Optimization
- [ ] Database connection pooling configured
- [ ] Indexes created on frequently queried columns
- [ ] Query optimization (avoid N+1 queries)
- [ ] Caching implemented for frequently accessed data
- [ ] Rate limiting configured
- [ ] Async operations used throughout

### Frontend Optimization
- [ ] Code splitting implemented
- [ ] Images optimized and lazy loaded
- [ ] Components memoized (React.memo)
- [ ] Unnecessary re-renders eliminated
- [ ] Bundle size analyzed and optimized
- [ ] Caching headers configured

### Infrastructure Optimization
- [ ] Multi-stage Docker builds optimized
- [ ] Container base images minimal
- [ ] Resource limits set (CPU, memory)
- [ ] Auto-scaling configured
- [ ] CDN configured for static assets
- [ ] Database backups scheduled

---

## 🔐 Security Checklist

### Code-Level Security
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (React auto-escaping)
- [ ] CSRF protection enabled
- [ ] Password hashing (bcrypt 12+ rounds)
- [ ] JWT secret key strong (32+ characters)
- [ ] Secrets not hardcoded (use env vars)

### Infrastructure Security
- [ ] HTTPS/TLS enabled
- [ ] CORS configured to specific origins
- [ ] Security headers set (CSP, X-Frame-Options, etc.)
- [ ] Database backups encrypted
- [ ] Secrets encrypted at rest
- [ ] Rate limiting enabled
- [ ] DDoS protection configured

### Operational Security
- [ ] Regular dependency updates
- [ ] Security vulnerability scanning
- [ ] Access control and RBAC
- [ ] Audit logging enabled
- [ ] Incident response plan documented
- [ ] Regular security testing
- [ ] Team security training completed

---

## 📞 Getting Help

### Documentation
1. **EXECUTIVE_SUMMARY.md** - High-level overview
2. **PMA_Rewrite_Guide.md** - Detailed architecture
3. **Backend_Implementation.md** - Code examples
4. **Migration_Roadmap.md** - Step-by-step guide
5. **API Docs** - http://localhost:8000/api/docs

### Resources
- FastAPI: https://fastapi.tiangolo.com
- SQLAlchemy: https://docs.sqlalchemy.org
- React: https://react.dev
- Tailwind: https://tailwindcss.com
- Docker: https://docs.docker.com

### Team Support
- Code reviews for all PRs
- Pair programming sessions
- Architecture discussions
- Performance optimization workshops

---

## ✨ Best Practices Summary

### Code Organization
- Keep services small and focused (Single Responsibility)
- Use dependency injection for testability
- Organize by feature, not by layer
- Keep functions pure and testable
- Document complex logic

### Testing Strategy
- Write tests as you code
- Aim for >80% coverage
- Test happy paths and edge cases
- Mock external dependencies
- Use fixtures for setup/teardown

### Deployment Process
- Automate everything with CI/CD
- Use blue-green deployment
- Monitor metrics before/after
- Have rollback plan ready
- Communicate with team

### Security Mindset
- Never trust user input
- Assume breach has occurred
- Encrypt sensitive data
- Log security events
- Keep dependencies updated
- Regular security reviews

---

## 🎉 Quick Wins (First Day)

```bash
# 1. Get the code
git clone https://github.com/ashu-duppati12/pma.git && cd pma

# 2. Start services
docker-compose up -d

# 3. Create a test user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "SecurePass123!",
    "full_name": "Test User"
  }'

# 4. View API documentation
open http://localhost:8000/api/docs

# 5. Access frontend
open http://localhost:3000

# 6. Run tests
pytest backend/auth-service/tests/ --verbose

# 7. Check code quality
black --check backend/auth-service/app/
mypy backend/auth-service/app/
```

**Expected Result**: All services running, tests passing, docs accessible! ✅

---

## 📅 30-Day Roadmap

| Period | Tasks |
|--------|-------|
| Days 1-3 | Setup, understand architecture, local environment |
| Days 4-7 | Backend core features, database |
| Days 8-12 | Frontend components, forms |
| Days 13-16 | Integration, API testing |
| Days 17-21 | Performance optimization, security audit |
| Days 22-27 | Documentation, team training |
| Days 28-30 | Final testing, production deployment |

---

**Version**: 1.0  
**Last Updated**: December 2025  
**Status**: Ready for Implementation 🚀

---

Keep this card handy while implementing the rewrite. Good luck! 💪