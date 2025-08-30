# FR-3 Post-Quantum Cryptography (PQC) PoC

This repository contains a Proof-of-Concept (PoC) implementation for securing communications (e.g., for ROS 2) using post-quantum digital signatures (ML-DSA/Dilithium) provided by the [liboqs](https://openquantumsafe.org/) project.

This PoC demonstrates:
-   Generating quantum-resistant keypairs.
-   Creating and signing JSON-based messages.
-   Verifying messages with replay and timestamp-window protection.
-   A test suite for correctness, tampering, and other attack vectors.

Security hardening highlights:
-   Secret key file is written atomically with 0600 permissions; verification refuses secrets with permissive modes.
-   Verifier enforces input limits (JSON ≤ 64KB, signature ≤ 8KB, canonical message ≤ 64KB) and basic type checks.
-   Nonce uses URL-safe Base64 without padding to ease transport.

## Version

Current version: **v0.1.0-pre** (Initial pre-release)

## Environment Setup

This project uses Python 3.12+ and [uv](https://docs.astral.sh/uv/) for environment management.

### 1. Prerequisites

- **Python 3.12+**
- **`uv`**: If you don't have `uv`, the setup script will try to install it via `pipx` or `brew`.
- **Build Tools**: A C compiler, `cmake`, and `ninja` are required to build the `liboqs` backend.
  - **On macOS**: `brew install cmake ninja`
  - **On Debian/Ubuntu**: `sudo apt-get install build-essential cmake ninja-build`

### 2. Automated Setup

A setup script is provided to create the virtual environment and install all dependencies, including `liboqs-python`.

First, ensure the script is executable:
```bash
chmod +x scripts/setup_liboqs_python.sh
```

Then, run it from the project root:
```bash
./scripts/setup_liboqs_python.sh
```
This script will:
1.  Create a virtual environment in `.venv/`.
2.  Install the required Python packages from `pyproject.toml`.
3.  Install the `liboqs-python` library and its native `liboqs` dependency.
4.  Run a quick verification to ensure the cryptographic primitives work correctly.

### 3. Activate Environment

Once the setup is complete, activate the virtual environment:
```bash
source .venv/bin/activate
```

## Usage

1.  **Generate Keys:**
    Create a new keypair. This will produce `ml_dsa_pub.json` (public key) and `ml_dsa_sec.json` (secret key).
    ```bash
    python keygen.py --pubkey-id controller-01
    ```

2.  **Sign a Sample Message:**
    Use the secret key to sign a sample command and save it to `signed_cmd.json`.
    ```bash
    python sign_verify.py --mode sign --sec ml_dsa_sec.json --pub ml_dsa_pub.json --out signed_cmd.json
    ```

3.  **Verify the Message:**
    Use the public key to verify the signature on the message.
    ```bash
    python sign_verify.py --mode verify --pub ml_dsa_pub.json --in signed_cmd.json
    ```

    Notes:
    - Ensure `ml_dsa_sec.json` keeps permissions at 0600; otherwise verification tools will refuse to load it.
    - Very large inputs are rejected to mitigate DoS (see limits above).

4.  **Run Automated PoC Tests:**
    The `schema.py` script contains a self-test suite that runs multiple scenarios.
    ```bash
    python schema.py
    ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
