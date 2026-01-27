# Contributing to Chronix

Thank you for your interest in contributing to Chronix.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   cd frontend && npm install
   ```

## Development

### Running the Application

```bash
chronix init    # First-time setup
chronix start   # Start the server
```

### Running Tests

```bash
# Backend tests
pytest

# Frontend build check
cd frontend && npm run build
```

## Code Style

- Python: Follow existing code patterns in the repository
- Keep imports organized (stdlib, third-party, local)
- Use type hints where practical
- Write docstrings for public functions and classes

## Submitting Changes

1. Create a branch for your changes
2. Make your changes with clear, descriptive commits
3. Ensure tests pass
4. Open a pull request with a clear description of the changes

## Licensing

Chronix is licensed under **AGPL-3.0-only**.

By submitting a pull request, you agree that:

- Your contributions are licensed under AGPL-3.0-only
- You have the right to submit the code under this license
- Your code does not contain material copied from incompatible sources

Do not submit code copied from projects with incompatible licenses (e.g., proprietary code, or code under licenses incompatible with AGPLv3).

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## Questions

Open an issue at https://github.com/icecubesandwich/chronix for questions or discussion.
