# 👨‍💻 Aegis Cloud Security Scanner - Developer Documentation

Welcome to the developer documentation for Aegis Cloud Security Scanner. This directory contains comprehensive technical documentation for contributors and developers.

## 📚 Documentation Structure

This developer manual is divided into 10 parts for easy navigation:

### Part 1: Getting Started
- [DEVELOPER_MANUAL_PART_1.md](DEVELOPER_MANUAL_PART_1.md)
  - Project overview and architecture
  - Development environment setup
  - Project structure and organization
  - Core technologies and dependencies

### Part 2: Backend Development
- [DEVELOPER_MANUAL_PART_2.md](DEVELOPER_MANUAL_PART_2.md)
  - Flask application structure
  - Database models and relationships
  - Authentication and authorization
  - Session management

### Part 3: Cloud Scanners
- [DEVELOPER_MANUAL_PART_3.md](DEVELOPER_MANUAL_PART_3.md)
  - AWS scanner implementation
  - GCP scanner implementation
  - Azure scanner implementation
  - Adding new cloud providers

### Part 4: Security Implementation
- [DEVELOPER_MANUAL_PART_4.md](DEVELOPER_MANUAL_PART_4.md)
  - Encryption and credential management
  - Input validation and sanitization
  - CSRF protection
  - Rate limiting

### Part 5: Frontend Development
- [DEVELOPER_MANUAL_PART_5.md](DEVELOPER_MANUAL_PART_5.md)
  - Template structure
  - JavaScript components
  - CSS architecture
  - Dark mode implementation

### Part 6: API Development
- [DEVELOPER_MANUAL_PART_6.md](DEVELOPER_MANUAL_PART_6.md)
  - RESTful API endpoints
  - Request/response formats
  - Error handling
  - API documentation

### Part 7: Testing & Quality Assurance
- [DEVELOPER_MANUAL_PART_7.md](DEVELOPER_MANUAL_PART_7.md)
  - Unit testing
  - Integration testing
  - Security testing
  - Performance testing

### Part 8: Deployment & DevOps
- [DEVELOPER_MANUAL_PART_8.md](DEVELOPER_MANUAL_PART_8.md)
  - Docker deployment
  - Production configuration
  - Monitoring and logging
  - Backup strategies

### Part 9: License System
- [DEVELOPER_MANUAL_PART_9.md](DEVELOPER_MANUAL_PART_9.md)
  - License validation logic
  - License generation (admin only)
  - Tier management
  - Usage tracking

### Part 10: Advanced Topics & Contributing
- [DEVELOPER_MANUAL_PART_10.md](DEVELOPER_MANUAL_PART_10.md)
  - Performance optimization
  - Scalability considerations
  - Contributing guidelines
  - Code style and standards

## 🚀 Quick Start for Developers

### Prerequisites
- Python 3.13+ (or 3.8+)
- Git
- Docker (optional)
- Cloud provider accounts (AWS, GCP, Azure) for testing

### Development Setup

```bash
# Clone the repository
git clone https://github.com/SubashUduwaka/cloud-security-scanner.git
cd cloud-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python app.py
```

### Making Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the code style guidelines (Part 10)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run tests
   pytest

   # Check code style
   flake8 .
   ```

4. **Commit and push**
   ```bash
   git add .
   git commit -m "Add: your feature description"
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request**
   - Go to GitHub and create a PR
   - Describe your changes
   - Link related issues

## 🔧 Development Tools

### Recommended IDE Setup
- **VSCode** with extensions:
  - Python
  - Pylance
  - Docker
  - GitLens

- **PyCharm** (Professional or Community)

### Code Quality Tools
- **Linting**: flake8, pylint
- **Formatting**: black, autopep8
- **Type Checking**: mypy
- **Testing**: pytest

## 📋 Code Standards

### Python Style Guide
- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for all public functions
- Keep functions small and focused

### Commit Message Format
```
Type: Brief description

Detailed description (optional)

- Bullet points for changes
- Link to issues: #123
```

**Types**: Add, Update, Fix, Refactor, Docs, Test, Chore

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────┐
│           Frontend (Templates)              │
│  HTML5, CSS3, JavaScript, Chart.js          │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│         Flask Application (app.py)          │
│  Routes, Controllers, Business Logic        │
└─────┬──────────┬───────────┬────────────────┘
      │          │           │
┌─────▼────┐ ┌──▼───────┐ ┌─▼──────────┐
│ Scanners │ │  Tools   │ │  Licenses  │
│ AWS/GCP/ │ │  Crypto  │ │  Manager   │
│  Azure   │ │ Validate │ │ Middleware │
└──────────┘ └──────────┘ └────────────┘
      │          │           │
┌─────▼──────────▼───────────▼────────────────┐
│         Database (SQLAlchemy)               │
│       SQLite / PostgreSQL                   │
└─────────────────────────────────────────────┘
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scanners.py

# Run with coverage
pytest --cov=. --cov-report=html
```

### Writing Tests
- Place tests in `tests/` directory
- Follow naming convention: `test_*.py`
- Use fixtures for common setup
- Mock external API calls

## 🐛 Debugging

### Debug Mode
```python
# Set in app.py
app.run(debug=True)
```

### Logging
```python
from tools.aegis_logger import live_logger

live_logger.info("Debug message")
live_logger.error("Error message")
```

### Common Issues
- **Import errors**: Check virtual environment activation
- **Database errors**: Delete `instance/` folder and restart
- **API errors**: Verify cloud credentials

## 📞 Getting Help

### For Developers
- 📖 Read the relevant manual part
- 🔍 Search existing issues
- 💬 Open a discussion
- 📧 Email: aegis.aws.scanner@gmail.com

### Resources
- [Main README](../../README.md)
- [User Manual](../../docs/USER_MANUAL.md)
- [Deployment Guide](../../docs/DEPLOYMENT_GUIDE.md)
- [Contributing Guidelines](../../CONTRIBUTING.md)

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](../../CONTRIBUTING.md) for:
- How to report bugs
- How to suggest features
- Pull request process
- Code review guidelines

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](../../LICENSE) file for details.

---

**Happy Coding! 🚀**

*Built with ❤️ by Subash Dananjaya Uduwaka*
