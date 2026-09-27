import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

from file_crypto import FileCryptoError, decrypt_file, encrypt_file, generate_and_save_key, load_key


class FileCryptoTests(unittest.TestCase):
    def test_generate_and_load_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            key_path = Path(temp_dir) / "secret.key"
            generate_and_save_key(key_path)
            loaded = load_key(key_path)
            Fernet(loaded)
            self.assertEqual(len(loaded), 44)

    def test_load_missing_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(FileCryptoError, "Key file not found"):
                load_key(Path(temp_dir) / "missing.key")

    def test_round_trip_restores_original_bytes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            key = Fernet.generate_key()
            original = b"Codveda Level 3 encryption demo.\nSecond line.\n"
            input_path = root / "original.txt"
            encrypted_path = root / "original.txt.enc"
            restored_path = root / "restored.txt"
            input_path.write_bytes(original)
            encrypt_file(input_path, encrypted_path, key)
            self.assertNotEqual(encrypted_path.read_bytes(), original)
            decrypt_file(encrypted_path, restored_path, key)
            self.assertEqual(restored_path.read_bytes(), original)

    def test_missing_input_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaisesRegex(FileCryptoError, "Input file not found"):
                encrypt_file(root / "missing.txt", root / "out.enc", Fernet.generate_key())

    def test_same_input_and_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "data.txt"
            input_path.write_text("hello", encoding="utf-8")
            with self.assertRaisesRegex(FileCryptoError, "must be different"):
                encrypt_file(input_path, input_path, Fernet.generate_key())

    def test_invalid_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "data.txt"
            input_path.write_text("hello", encoding="utf-8")
            with self.assertRaisesRegex(FileCryptoError, "Invalid Fernet key"):
                encrypt_file(input_path, root / "data.enc", b"not-a-valid-key")

    def test_wrong_key_cannot_decrypt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "data.txt"
            encrypted = root / "data.enc"
            restored = root / "restored.txt"
            source.write_bytes(b"secret")
            encrypt_file(source, encrypted, Fernet.generate_key())
            with self.assertRaisesRegex(FileCryptoError, "Decryption failed"):
                decrypt_file(encrypted, restored, Fernet.generate_key())

    def test_corrupted_ciphertext_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "data.txt"
            encrypted = root / "data.enc"
            restored = root / "restored.txt"
            source.write_bytes(b"secret")
            key = Fernet.generate_key()
            encrypt_file(source, encrypted, key)
            encrypted.write_bytes(b"corrupted")
            with self.assertRaisesRegex(FileCryptoError, "Decryption failed"):
                decrypt_file(encrypted, restored, key)


if __name__ == "__main__":
    unittest.main()
