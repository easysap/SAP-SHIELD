# Contributing to SAP Shield

Thank you for your interest in contributing to SAP Shield! This project exists to make insider threat detection accessible to organizations of all sizes, and community contributions are essential to that mission.

## How to Contribute

### Reporting Bugs

- Use the [GitHub Issues](../../issues) page
- Include your environment details (OS, Python version, Docker version)
- Provide steps to reproduce the issue
- Include relevant log output

### Suggesting Features

- Open a GitHub Issue with the `enhancement` label
- Describe the use case and expected behavior
- If proposing a new detection scenario, explain the threat model

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for your changes
4. Ensure all tests pass: `pytest tests/`
5. Follow the code style (see below)
6. Commit with clear messages: `git commit -m "Add mass download detection for SE16N"`
7. Push and open a Pull Request

### Code Style

- Python: Follow PEP 8, use type hints
- Use `black` for formatting and `ruff` for linting
- Docstrings for all public functions and classes
- Keep functions focused and under 50 lines where possible

### Testing

- All new features must include tests
- Detection rules must include test cases with expected outcomes
- Run the full suite before submitting: `pytest tests/ -v`

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sap-shield.git
cd sap-shield

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## Security Considerations

If you discover a security vulnerability, please do NOT open a public issue. Instead, email saharguer99@gmail.com (or the maintainer directly) with details.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.
