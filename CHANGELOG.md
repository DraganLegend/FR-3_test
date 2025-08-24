# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (Future work will be listed here)

## [0.1.0-pre] - 2025-08-24

### Added
- Initial Proof-of-Concept for PQC signing and verification.
- `keygen.py`: Script to generate ML-DSA keypairs.
- `sign_verify.py`: CLI tool to sign and verify JSON payloads.
- `schema.py`: Standalone script with message schema definitions and self-tests.
- Environment setup using `uv` with `.python-version` and `pyproject.toml`.
- Initial Git repository setup with `.gitignore`.
- Compatibility fixes in `schema.py` and `sign_verify.py` to support the latest `liboqs-python` API.
