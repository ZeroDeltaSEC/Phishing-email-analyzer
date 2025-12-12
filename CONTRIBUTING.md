# Contributing to Advanced Phishing Email Analyzer

Thank you for your interest in contributing to the Advanced Phishing Email Analyzer! 🎯

## 🤝 How to Contribute

We welcome contributions from the community! Here are several ways you can help:

### 1. Report Bugs
If you find a bug, please [create an issue](https://github.com/yourusername/phishing-analyzer/issues/new) with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)
- Relevant logs or screenshots

### 2. Suggest Enhancements
Have an idea for a new feature? [Open an issue](https://github.com/yourusername/phishing-analyzer/issues/new) describing:
- The problem your enhancement solves
- Your proposed solution
- Any implementation considerations
- Examples of use cases

### 3. Submit Pull Requests
We love pull requests! To submit one:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/AmazingFeature`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes**: `git commit -m 'Add some AmazingFeature'`
6. **Push to the branch**: `git push origin feature/AmazingFeature`
7. **Open a Pull Request**

---

## 📋 Pull Request Guidelines

### Before Submitting
- [ ] Code follows the existing style and conventions
- [ ] All tests pass
- [ ] Documentation is updated (if needed)
- [ ] Commit messages are clear and descriptive
- [ ] Changes are focused and atomic

### PR Description Should Include
- What changes were made and why
- Any breaking changes
- Screenshots (if UI changes)
- Related issues (use `Fixes #123` or `Closes #456`)

---

## 🎯 Areas for Contribution

### High Priority
- **YARA Rules**: Add more malware detection patterns to `patterns/malware.yar`
- **Pattern Detection**: Enhance phishing pattern detection in `modules/pattern_detector.py`
- **File Analyzers**: Add support for new file formats in `modules/file_analyzer.py`
- **Documentation**: Improve documentation and add more examples

### Medium Priority
- **AI Prompts**: Improve AI analysis prompts in `modules/ai_analyzer.py`
- **URL Analysis**: Enhance URL detonation and analysis
- **Testing**: Add unit tests and integration tests
- **Performance**: Optimize analysis speed

### Low Priority / Nice to Have
- **Web Interface**: Build a web dashboard
- **REST API**: Create an API interface
- **Database Support**: Add database integration for storing results
- **Machine Learning**: Implement ML models for detection

---

## 🛠️ Development Setup

### Prerequisites
- Python 3.8+
- Git
- Linux environment (or WSL on Windows)

### Setup Instructions

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/phishing-analyzer.git
cd phishing-analyzer

# Install dependencies
pip3 install -r requirements.txt

# Install development dependencies
pip3 install pytest black flake8

# Run tests (when available)
pytest tests/

# Format code
black .

# Lint code
flake8 .
```

---

## 📝 Code Style Guidelines

### Python Code Style
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and under 50 lines when possible
- Use type hints where applicable

### Example
```python
def analyze_email(email_path: str) -> dict:
    """
    Analyze an email file for phishing indicators.
    
    Args:
        email_path: Path to the .eml file
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        FileNotFoundError: If email file doesn't exist
    """
    # Implementation here
    pass
```

### Documentation Style
- Use Markdown for documentation files
- Keep README concise and clear
- Add code examples where helpful
- Include screenshots for visual features

---

## 🧪 Testing Guidelines

### Writing Tests
- Write unit tests for new functions
- Test edge cases and error conditions
- Use descriptive test names

### Example
```python
def test_url_detonation_with_valid_url():
    """Test URL detonation with a valid HTTP URL"""
    result = detonate_url("http://example.com")
    assert result['status'] == 'success'
    assert 'screenshot' in result
```

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_url_detonator.py

# Run with coverage
pytest --cov=modules tests/
```

---

## 📚 Documentation Contributions

### Areas Needing Documentation
- More usage examples
- Video tutorials
- Architecture diagrams
- API documentation (when implemented)
- Translation to other languages

### Documentation Style Guide
- Use clear, concise language
- Include code examples
- Add screenshots where helpful
- Keep it beginner-friendly

---

## 🔒 Security Considerations

### Reporting Security Issues
If you discover a security vulnerability, **DO NOT** open a public issue. Instead:
1. Email the maintainer directly
2. Provide detailed information about the vulnerability
3. Give us time to fix it before public disclosure

### Security Best Practices
- Never commit sensitive data (API keys, passwords, etc.)
- Test security-related changes thoroughly
- Consider impact on analysis VM isolation
- Document any security implications

---

## 📄 Commit Message Guidelines

### Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples
```
feat(url-detonator): Add screenshot capture for suspicious URLs

Implemented automatic screenshot capture when a URL is flagged
as suspicious based on redirect count and SSL issues.

Closes #42
```

```
fix(file-analyzer): Handle corrupt PDF files gracefully

Added try-catch block to prevent crashes when analyzing
malformed PDF files. Now logs error and continues analysis.

Fixes #38
```

---

## 🏆 Recognition

Contributors will be recognized in:
- GitHub contributors list
- CONTRIBUTORS.md file (coming soon)
- Release notes

---

## 📞 Getting Help

Need help with your contribution?

- **Discord**: [Join our community](https://discord.gg/your-invite) (if available)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/phishing-analyzer/discussions)
- **Email**: [Your email] (for private inquiries)

---

## 📜 License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

## 🙏 Thank You!

Every contribution, no matter how small, helps make this tool better for the security community. Thank you for taking the time to contribute!

---

**Questions?** Feel free to ask in [Discussions](https://github.com/yourusername/phishing-analyzer/discussions) or open an issue.
