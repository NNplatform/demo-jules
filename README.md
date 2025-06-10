# PGP Encryption/Decryption Scripts

## Overview
These scripts provide a set of Python utilities to perform Pretty Good Privacy (PGP) operations, including key pair generation, data encryption, and data decryption. They leverage the `python-gnupg` library to interact with GnuPG.

## Features
- **PGP Key Pair Generation:** Creates new RSA 2048-bit key pairs (public and private keys) associated with a name, email, and passphrase. It can also reuse existing keys if found for the given email.
- **Data Encryption:** Encrypts string data using a recipient's PGP public key (identified by fingerprint or email).
- **Data Decryption:** Decrypts PGP-encrypted messages using the corresponding private key and its passphrase.

## Requirements
- **Python 3:** The scripts are written for Python 3.
- **GnuPG (GPG):** The `python-gnupg` library is a wrapper around the GnuPG software. You must have GnuPG installed on your system.
    - **Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install gnupg`
    - **macOS (using Homebrew):** `brew install gnupg`
    - **Windows:** Download Gpg4win from [https://www.gpg4win.org/](https://www.gpg4win.org/)
- **python-gnupg:** The Python library to interface with GnuPG.

## Setup
1.  **Install GnuPG:** Follow the instructions above for your operating system if you don't already have it installed.
2.  **Install python-gnupg:**
    ```bash
    pip install python-gnupg
    ```

## Usage
The primary script to run for a demonstration of the encryption/decryption workflow is `main.py`.

-   **`main.py`:**
    -   This script demonstrates the end-to-end process:
        1.  Prompts for user details (name, email, passphrase - hardcoded in the example but illustrates the flow).
        2.  Generates a new PGP key pair if one doesn't exist for the email or uses an existing one.
        3.  Encrypts a sample message.
        4.  Decrypts the encrypted message.
        5.  Verifies that the decrypted message matches the original.
    -   To run it:
        ```bash
        python main.py
        ```
    -   When a new key is generated, or when data is decrypted, GnuPG (and thus these scripts) may require the passphrase you provided. The `python-gnupg` library handles the passphrase prompt mechanism, which might be a simple terminal prompt or a GPG agent GUI prompt depending on your system's GPG configuration.

-   **`pgp_key_utils.py`:**
    -   This file is a utility module containing the core functions:
        -   `generate_key_pair(name, email, passphrase)`: Manages key generation or retrieval.
        -   `encrypt_data(data, recipient_key_id)`: Encrypts data.
        -   `decrypt_data(encrypted_data, passphrase)`: Decrypts data.
    -   It can also be run directly (`python pgp_key_utils.py`) to see its own example usage, which is similar to `main.py` but uses different example user details.

## Example
Running `python main.py` for the first time with a new user might produce output similar to this:

```
--- PGP Encryption/Decryption Demo ---

Step 1: Generate/Retrieve PGP Key Pair
Generating new key for Alice Wonderland <alice@wonderland.io>...
Key generated successfully!
Fingerprint: <SOME_FINGERPRINT_HASH>
Using key with ID (Fingerprint): <SOME_FINGERPRINT_HASH>

Step 2: Encrypt Message
Encrypted Message:
-----BEGIN PGP MESSAGE-----
...
(Encrypted PGP block)
...
-----END PGP MESSAGE-----

Step 3: Decrypt Message
Decrypted Message:
Hello Bob! This is a top secret message.

Step 4: Verification
SUCCESS: Decrypted message matches the original message!
```
Subsequent runs for the same user will show "Using existing key for..." in Step 1.

## Important Notes
-   **Security:** Your private keys are protected by the passphrase you provide. Choose a strong, unique passphrase. **Anyone with access to your private key and its passphrase can decrypt your messages.**
-   **Key Management:** Generated PGP keys are stored in your system's GPG keyring, managed by GnuPG. You can list your keys using GPG command-line tools (e.g., `gpg --list-keys`, `gpg --list-secret-keys`).
-   **Passphrase Prompts:** Depending on your GPG configuration (especially if you use a GPG agent like `gpg-agent`), you might be prompted for your passphrase by a GUI pop-up rather than directly in the terminal where you run the Python script.
-   **Trust Model:** For encryption, `python-gnupg` (and GPG itself) usually requires keys to be trusted. The `encrypt_data` function in these scripts uses `always_trust=True` for simplicity in this example context. In real-world scenarios, proper key validation and trust management are crucial.
```
