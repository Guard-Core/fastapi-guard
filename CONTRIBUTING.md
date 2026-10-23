Contributing to FastAPI Guard
=============================

Thank you for considering contributing to FastAPI Guard! This document outlines the process for contributing to this Python library and helps ensure a smooth collaboration experience.

. Code of Conduct
----------------

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

___

How Can I Contribute?
---------------------

. Reporting Bugs
--------------

Before creating bug reports, please check the issue tracker to avoid duplicates. When you create a bug report, include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples (e.g., HTTP requests that trigger the issue)
- Describe the behavior you observed and why it's problematic
- Include logs, error messages, and Python version
- Specify your environment: OS, Python version, FastAPI version, etc.

. Suggesting Enhancements
-----------------------

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a detailed description of the proposed functionality
- Explain why this enhancement would be useful to FastAPI Guard users
- Include examples of how it would be used if applicable
- List any relevant references or examples from other libraries

. Pull Requests
-------------

- Fill in the required template
- Follow the Python style guides (PEP 8)
- Include tests for new features or bug fixes
- Update documentation for significant changes
- Ensure the test suite passes
- Make sure your code lints (ruff, mypy)

. Development Setup
-----------------

1. Fork and clone the repository

2. The project uses Docker for development and testing. Make sure you have Docker and Docker Compose installed on your system.

3. You can use the provided Makefile commands to set up your development environment:

```bash
# Install dependencies using 'uv'
make install

# To stop all containers
make stop
```

. Testing
-------

The project supports Python 3.10, 3.11, 3.12, 3.13 and 3.14. Tests are run using Docker containers:

```bash
# Run tests with the default Python version (3.10)
make test

# Run tests with all supported Python versions
make test-all

# Run tests with a specific Python version
make test-3.11

# Run tests locally (if you have 'uv' installed)
make local-test
```

. Style Guidelines
----------------

This project uses:

- [Ruff](https://github.com/astral-sh/ruff) for code formatting and linting
- [mypy](https://mypy.readthedocs.io/) for type checking

Before submitting a PR, make sure your code passes all style checks:

```bash
make lint
make fix
```

and

```bash
make lint-docs
make fix-docs
```

. Documentation
-------------

The documentation for FastAPI Guard is built with MkDocs. To build and view the documentation locally:

```bash
make serve-docs
```

Docs build only on Python 3.14 (`make serve-docs` and the docs workflow use it): on 3.10 the newest mkdocstrings (1.0.6) fails with pymdown-extensions 12 with `TypeError: Highlight.__init__() missing 1 required positional argument: 'md'`.

Please update the documentation when making significant changes.

___

Versioning
----------

This project follows [Semantic Versioning](https://semver.org/).

. Release Process
---------------

1. Update version in `pyproject.toml`
2. Update `docs/release-notes.md`
3. Create a new GitHub release with release notes
4. CI will automatically publish to PyPI

___

Questions?
----------

If you have questions about the development process or need help, feel free to open an issue for discussion.

Thank you for contributing to FastAPI Guard!
