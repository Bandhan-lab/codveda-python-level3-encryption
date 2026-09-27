"""Secure file encryption and decryption using Fernet symmetric cryptography.

Codveda Technology Python Development Internship - Level 3 Task 2.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_KEY_FILE = Path("secret.key")


class FileCryptoError(Exception):
    """Raised when a file encryption/decryption operation cannot be completed."""


def generate_key() -> bytes:
    return Fernet.generate_key()


def save_key(key: bytes, key_path: Path) -> None:
    try:
        Fernet(key)
    except (TypeError, ValueError) as exc:
        raise FileCryptoError("Invalid Fernet key.") from exc

    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(key_path, flags, 0o600)
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(key)
    except FileExistsError as exc:
        raise FileCryptoError(f"Key file already exists: {key_path}") from exc
    except OSError as exc:
        raise FileCryptoError(f"Could not save key file: {key_path}: {exc}") from exc


def load_key(key_path: Path) -> bytes:
    if not key_path.is_file():
        raise FileCryptoError(f"Key file not found: {key_path}")
    try:
        key = key_path.read_bytes().strip()
    except OSError as exc:
        raise FileCryptoError(f"Could not read key file: {key_path}: {exc}") from exc

    try:
        Fernet(key)
    except (TypeError, ValueError) as exc:
        raise FileCryptoError("Key file does not contain a valid Fernet key.") from exc
    return key


def generate_and_save_key(key_path: Path) -> None:
    save_key(generate_key(), key_path)


def _validate_paths(input_path: Path, output_path: Path) -> None:
    if not input_path.is_file():
        raise FileCryptoError(f"Input file not found: {input_path}")
    if input_path.resolve() == output_path.resolve():
        raise FileCryptoError("Input and output files must be different.")
    if output_path.exists():
        try:
            if input_path.samefile(output_path):
                raise FileCryptoError("Input and output files must be different.")
        except OSError:
            pass
        raise FileCryptoError(f"Output file already exists: {output_path}")


def _read_input(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FileCryptoError(f"Could not read input file: {path}: {exc}") from exc


def _write_output(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output_file:
            output_file.write(data)
    except FileExistsError as exc:
        raise FileCryptoError(f"Output file already exists: {path}") from exc
    except OSError as exc:
        raise FileCryptoError(f"Could not write output file: {path}: {exc}") from exc


def encrypt_file(input_path: Path, output_path: Path, key: bytes) -> None:
    _validate_paths(input_path, output_path)

    try:
        cipher = Fernet(key)
    except (TypeError, ValueError) as exc:
        raise FileCryptoError("Invalid Fernet key.") from exc

    plaintext = _read_input(input_path)
    _write_output(output_path, cipher.encrypt(plaintext))


def decrypt_file(input_path: Path, output_path: Path, key: bytes) -> None:
    _validate_paths(input_path, output_path)

    try:
        cipher = Fernet(key)
        plaintext = cipher.decrypt(_read_input(input_path))
    except (TypeError, ValueError) as exc:
        raise FileCryptoError("Invalid Fernet key.") from exc
    except InvalidToken as exc:
        raise FileCryptoError("Decryption failed: invalid key or corrupted file.") from exc

    _write_output(output_path, plaintext)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt files using Fernet symmetric cryptography."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_parser = subparsers.add_parser("generate-key", help="Generate and save a new Fernet key.")
    key_parser.add_argument(
        "--key-file",
        type=Path,
        default=DEFAULT_KEY_FILE,
        help="Path where the key will be stored (default: secret.key).",
    )

    for command in ("encrypt", "decrypt"):
        command_parser = subparsers.add_parser(
            command, help=f"{command.capitalize()} a file."
        )
        command_parser.add_argument("input", type=Path, help="Input file path.")
        command_parser.add_argument("output", type=Path, help="Output file path.")
        command_parser.add_argument(
            "--key-file",
            type=Path,
            default=DEFAULT_KEY_FILE,
            help="Path to the Fernet key file (default: secret.key).",
        )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "generate-key":
            generate_and_save_key(args.key_file)
            print(f"Key generated: {args.key_file}")
            print("Keep this key private. You need the same key to decrypt your files.")
            return 0

        key = load_key(args.key_file)
        if args.command == "encrypt":
            encrypt_file(args.input, args.output, key)
            print(f"Encrypted: {args.input} -> {args.output}")
        else:
            decrypt_file(args.input, args.output, key)
            print(f"Decrypted: {args.input} -> {args.output}")
        return 0
    except FileCryptoError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
