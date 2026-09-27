# Codveda Python — Level 3 Task 2: File Encryption & Decryption

A secure command-line file encryption and decryption tool built with **Python** and **Fernet symmetric authenticated cryptography**.

Developed for the **Codveda Technology Python Development Internship — Level 3, Task 2**.

## Task requirements

The Codveda brief requires the project to accept an input file, encrypt it using Caesar cipher or Fernet, decrypt an encrypted file, save new output files, and restore the original content. This implementation uses **Fernet** with key management, validation, and automated tests.

## Features

- Fernet authenticated encryption through the `cryptography` package
- Generates and saves a fresh Fernet key
- Encrypts arbitrary file bytes without modifying the original
- Decrypts ciphertext back to the exact original bytes
- Rejects missing files, invalid keys, corrupted ciphertext, and same-file overwrite attempts
- Refuses to overwrite an existing key through the CLI
- Automated unit tests with temporary directories
- No secrets committed to the repository

## Project structure

```text
codveda-python-level3-encryption/
├── file_crypto.py
├── requirements.txt
├── tests/
│   └── test_file_crypto.py
├── .gitignore
└── README.md
```

## Setup

Python 3.11+ is recommended.

```bash
git clone https://github.com/Bandhan-lab/codveda-python-level3-encryption.git
cd codveda-python-level3-encryption
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

### 1. Generate a key

```bash
python file_crypto.py generate-key --key-file secret.key
```

Keep `secret.key` private. The same key is required to decrypt the encrypted file.

### 2. Encrypt a file

```bash
printf 'Codveda encryption demo\nThis file will be restored exactly.\n' > sample.txt
python file_crypto.py encrypt sample.txt sample.txt.enc --key-file secret.key
```

The original `sample.txt` remains unchanged.

### 3. Decrypt the file

```bash
python file_crypto.py decrypt sample.txt.enc restored.txt --key-file secret.key
```

Verify the restored content:

```bash
cmp sample.txt restored.txt && echo "Restored content matches original"
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

The test suite covers key generation/loading, round-trip encryption/decryption, missing files, invalid keys, wrong keys, corrupted ciphertext, and overwrite protection.

## Security notes

Fernet provides authenticated symmetric encryption. Anyone with the key can decrypt the data, so **key management is the critical security responsibility**.

For production use, store encryption keys in a secure secret manager or OS-protected keystore rather than beside encrypted data. This educational project keeps the key-file workflow simple and local.

Do not commit real `secret.key` files or encrypted demo artifacts. The repository's `.gitignore` excludes them.

## Internship

**Program:** Codveda Technology — Python Development Internship  
**Level:** 3 — Advanced  
**Task:** 2 — File Encryption/Decryption  
**Domain:** Python Development
