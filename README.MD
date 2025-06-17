# Email Monitor 📧

Real-time email monitoring system with secure WebSocket and JWT authentication.

## 🏗️ Architecture

### Complete Project Structure
```
websocket/
├── main.py                    # Main entry point with CLI
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Development dependencies
├── .env.example              # Configuration example
├── .gitignore                # Git ignored files
├── Dockerfile                # Docker image for production
├── docker-compose.yml        # Docker Compose orchestration
├── README.md                 # Complete documentation
└── src/                      # Main source code
    ├── __init__.py           # Main package
    ├── main.py               # Main application
    ├── core/                 # Configuration and constants
    │   ├── __init__.py
    │   ├── config.py         # ✅ System configuration
    │   ├── constants.py      # ✅ Constants and enums
    │   └── exceptions.py     # ✅ Custom exceptions
    ├── auth/                 # Authentication system
    │   ├── __init__.py
    │   ├── jwt_manager.py    # ✅ JWT token management
    │   └── user_service.py   # ✅ User management and auth
    ├── security/             # Security modules
    │   ├── __init__.py
    │   ├── rate_limiter.py   # ✅ Rate limiting per IP/endpoint
    │   └── ip_filter.py      # ✅ IP filtering and blocking
    ├── websocket/            # WebSocket server
    │   ├── __init__.py
    │   └── server.py         # ✅ Secure WebSocket with auth
    ├── email/                # Email system
    │   ├── __init__.py
    │   ├── monitor.py        # ✅ Real-time IMAP monitor
    │   └── processor.py      # ✅ Secure email processor
    └── utils/                # System utilities
        ├── __init__.py
        └── logger.py         # ✅ Production logging system
```

### Applied Design Principles
- **Separation of Concerns (SoC)** - Each module has a single responsibility
- **Single Responsibility Principle (SRP)** - Classes with specific purpose
- **Dependency Injection** - Centralized configuration, easy testing
- **Factory Pattern** - Controlled object creation
- **Hexagonal Architecture** - Isolated core business logic

## 🚀 Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd websocket
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure environment variables
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Minimum required configuration
```bash
# In .env
EMAIL_SERVER=imap.gmail.com
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
JWT_SECRET_KEY=your-unique-secret-key
```

## 🎯 Usage

### Local Installation

#### Run in development mode
```bash
python main.py --debug
```

#### Run in production
```bash
python main.py
```

#### Test email connection
```bash
python main.py --test-email
```

#### Show version
```bash
python main.py --version
```

#### Custom configuration
```bash
python main.py --config /path/to/custom/.env
```

### Docker Installation

#### Quick development
```bash
# Create .env file with your configuration
cp .env.example .env

# Build and run
docker-compose up --build
```

#### Production
```bash
# Configure production variables in .env
ENVIRONMENT=production
SSL_CERT_FILE=/app/ssl/cert.pem
SSL_KEY_FILE=/app/ssl/key.pem

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f email-monitor
```

#### Useful Docker commands
```bash
# View status
docker-compose ps

# Restart service
docker-compose restart email-monitor

# Stop everything
docker-compose down

# Clean volumes
docker-compose down -v
```

## 🔧 Configuration

### Email
- **Gmail**: Use App Password, not regular password
- **Outlook**: Enable IMAP in settings
- **Others**: Verify IMAP SSL configuration

### JWT
- Generate unique secret key for production
- Configure expiration time according to needs

### Security
- Configure allowed IPs
- Adjust rate limiting settings
- Enable SSL/TLS in production

## 🌐 WebSocket API

### Authentication
```javascript
// With credentials
{
  "type": "login",
  "username": "admin",
  "password": "password"
}

// With token
{
  "type": "token_auth", 
  "token": "jwt-token"
}
```

### Email events
```javascript
{
  "type": "new_email",
  "id": "12345",
  "subject": "Email subject",
  "sender": "sender@domain.com",
  "text_content": "Content...",
  "attachments": [...],
  "security_flags": [...]
}
```

### Token refresh
```javascript
{
  "type": "refresh_token",
  "refresh_token": "refresh-jwt-token"
}
```

### Ping/Pong
```javascript
// Send
{"type": "ping"}

// Response
{"type": "pong"}
```

## 🔒 Security

### Implemented features
- ✅ JWT authentication with refresh tokens
- ✅ Rate limiting per IP and endpoint
- ✅ IP filtering and blocking
- ✅ Attachment validation and filtering
- ✅ XSS content sanitization
- ✅ Specialized security logging
- ✅ Account lockout for failed attempts
- ✅ Optional SSL/TLS
- ✅ Sensitive information filtering in logs

### Production recommendations
- Always use HTTPS/WSS
- Configure reverse proxy (nginx)
- Actively monitor security logs
- Rotate JWT keys periodically
- Keep dependencies updated
- Use valid SSL certificates
- Configure firewall appropriately

## 📊 Monitoring

### Available logs
- `logs/email_monitor.log` - General application logs
- `logs/security.log` - Specific security events

### System metrics
- Active WebSocket connections
- Emails processed per minute
- Rate limits exceeded
- Temporarily blocked IPs
- Failed authentication attempts
- System uptime

### Monitored security events
- Failed login attempts
- Automatically blocked IPs
- Detected dangerous attachments
- Rate limits exceeded
- Suspicious activity detected

## 🐛 Development

### Setup development environment
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Configure pre-commit hooks
pre-commit install
```

### Testing structure
```bash
# Unit tests
pytest tests/unit/

# Integration tests  
pytest tests/integration/

# Full coverage
pytest --cov=src tests/

# Linting and formatting
flake8 src/
black src/
isort src/
mypy src/
```

### Debug logs
```bash
python main.py --debug
```

### Development environment variables
```bash
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG
WEBSOCKET_HOST=localhost
MAX_CONNECTIONS=10
```

## 📝 Environment Configuration

### Development
```bash
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG
WEBSOCKET_HOST=localhost
MAX_CONNECTIONS=10
EMAIL_CHECK_INTERVAL=30
```

### Staging
```bash
ENVIRONMENT=staging
DEBUG=false
LOG_LEVEL=INFO
MAX_CONNECTIONS=50
SSL_CERT_FILE=/path/to/staging-cert.pem
SSL_KEY_FILE=/path/to/staging-key.pem
```

### Production
```bash
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=WARNING
SSL_CERT_FILE=/path/to/prod-cert.pem
SSL_KEY_FILE=/path/to/prod-key.pem
MAX_CONNECTIONS=1000
RATE_LIMIT_REQUESTS=100
JWT_SECRET_KEY=production-secret-key-very-long-and-secure
```

## 🚨 Troubleshooting

### Email connection error
**Symptom**: `EmailConnectionError` or `EmailAuthenticationError`
```bash
# Verify configuration
python main.py --test-email

# Check credentials in .env
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password-not-regular-password
```

**Solutions**:
- Verify credentials (use App Password for Gmail)
- Confirm IMAP is enabled
- Check firewall configuration
- Verify network connectivity

### WebSocket error
**Symptom**: Cannot connect to WebSocket
```bash
# Check if port is free
netstat -an | grep 8765

# Test local connection
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: test" -H "Sec-WebSocket-Version: 13" \
  http://localhost:8765/
```

**Solutions**:
- Verify port availability
- Check SSL configuration
- Verify certificate permissions
- Check firewall configuration

### JWT authentication error
**Symptom**: `TokenExpiredError` or `InvalidTokenError`
```bash
# Verify JWT configuration
grep JWT_SECRET_KEY .env
```

**Solutions**:
- Verify JWT_SECRET_KEY is configured
- Check admin user configuration
- Review security logs
- Verify server time synchronization

### Performance issues
**Symptom**: Slowness or timeouts
```bash
# Check system resources
docker stats email-monitor

# Review logs for errors
docker-compose logs email-monitor | grep ERROR
```

**Solutions**:
- Increase Docker resources
- Adjust email check intervals
- Optimize rate limiting configuration
- Review network connectivity

### Attachment issues
**Symptom**: Attachments not processed or security errors
```bash
# Review security logs
tail -f logs/security.log | grep attachment
```

**Solutions**:
- Verify allowed file types
- Adjust size limits
- Review security configuration
- Check disk space

## 📄 License

MIT License

Copyright (c) 2025 Email Monitor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

### 1. Fork and clone
```bash
git clone https://github.com/your-username/websocket.git
cd websocket
```

### 2. Create feature branch
```bash
git checkout -b feature/new-functionality
```

### 3. Develop with standards
- Follow existing modular architecture
- Add tests for new functionality
- Maintain test coverage > 80%
- Document public functions
- Use Python type hints

### 4. Testing
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ --cov=src

# Linting
flake8 src/
black src/
isort src/
mypy src/
```

### 5. Commit and Pull Request
```bash
git add .
git commit -m "feat: clear description of functionality"
git push origin feature/new-functionality
```

### Code Standards
- **Python**: PEP 8, type hints, docstrings
- **Commits**: Conventional Commits (feat:, fix:, docs:)
- **Tests**: pytest, minimum 80% coverage
- **Security**: Validate inputs, logs without sensitive info

### Areas needing contribution
- [ ] More comprehensive integration tests
- [ ] Support for multiple IMAP servers
- [ ] Web administration dashboard
- [ ] Advanced metrics and monitoring
- [ ] WebSocket API documentation
- [ ] External database support
- [ ] Notification system integration
- [ ] Support for other protocols (POP3, Exchange)
- [ ] Complementary REST API
- [ ] Plugin/extension system

### Reporting Issues
- Use GitHub issue template
- Include relevant logs (without sensitive info)
- Describe steps to reproduce
- Specify version and environment
- Provide minimal configuration to reproduce

### Code Review
- All PRs require review
- Automated tests must pass
- Documentation must be updated
- Breaking changes require discussion