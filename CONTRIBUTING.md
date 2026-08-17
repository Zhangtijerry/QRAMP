# Contributing to QRAMP

Thank you for your interest in contributing to QRAMP! This document provides
guidelines for contributing to the project.

## Getting Started

1. Fork the repository and clone it locally.
2. Install the development dependencies:

```bash
pip install -e ".[dev,source,validate,versions]"
```

3. Run the test suite to verify your setup:

```bash
pytest -q
```

## How to Contribute

### Reporting Issues

- Use the [GitHub issue tracker](https://github.com/Zhangtijerry/QRAMP/issues).
- Include a minimal reproducible example when reporting bugs.
- Describe expected vs. actual behaviour clearly.

### Submitting Changes

1. Create a feature branch from `main`.
2. Write tests for any new functionality.
3. Ensure all tests pass (`pytest -q`).
4. Keep commits focused and well-described.
5. Open a pull request with a clear description of the change.

### Extending QRAMP

QRAMP is designed for extensibility in three ways:

- **Custom collectors** — register under the `qramp.collectors` entry point
  to scan a site-specific technology (HSM, code-signing pipeline, etc.).
- **Rule packs** — edit the YAML rule pack or supply a custom one via
  `--rules`. Use `qramp lint-rules` to validate changes.
- **Provider maps and alias maps** — extend `data/provider-map.yaml` or
  `data/manifest-aliases.yaml` to teach QRAMP about new libraries.
- **Site query overrides** — add `.scm` files under `.qramp/queries/` to
  detect internal crypto wrappers without modifying QRAMP's code.

### Code Style

- Follow PEP 8.
- Add docstrings to public functions and classes.
- Include SPDX license identifiers in new source files.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
