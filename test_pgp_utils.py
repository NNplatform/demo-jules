import unittest
import pgp_key_utils
import tempfile
import shutil
import os
import gnupg # For deleting keys if necessary, and for constants

class TestPGPUtils(unittest.TestCase):
    test_gnupghome = None
    gpg = None

    @classmethod
    def setUpClass(cls):
        # Create a temporary directory for GPG home for all tests in this class
        cls.test_gnupghome = tempfile.mkdtemp(prefix="test_gpg_")
        # It's important that GnuPG can write here, permissions are usually fine with mkdtemp
        # Initialize a GPG object that tests can use or functions can use internally via kwargs
        cls.gpg_kwargs = {'gnupghome': cls.test_gnupghome}
        # Optionally, create a gpg object for direct manipulation if needed for setup/cleanup
        cls.gpg_obj_for_cleanup = gnupg.GPG(gnupghome=cls.test_gnupghome)
        print(f"Using temporary GPG home: {cls.test_gnupghome}")

    @classmethod
    def tearDownClass(cls):
        # Clean up: Remove the temporary GPG home directory
        if cls.test_gnupghome and os.path.exists(cls.test_gnupghome):
            shutil.rmtree(cls.test_gnupghome)
            print(f"Cleaned up temporary GPG home: {cls.test_gnupghome}")

    def setUp(self):
        # This method is called before each test.
        # Ensure no keys from previous tests are lingering if tests are not perfectly isolated by class setup.
        # For now, assuming setUpClass and tearDownClass handle isolation sufficiently.
        pass

    def tearDown(self):
        # This method is called after each test.
        # If we needed to delete keys after each test, this would be a place.
        # However, with a fresh gnupghome per class, it's less critical.
        pass

    def test_01_generate_key_pair(self):
        print("\nRunning test_01_generate_key_pair...")
        name = "Test KeyGen"
        email = "keygen@example.com"
        passphrase = "testgenpass"
        fingerprint = pgp_key_utils.generate_key_pair(name, email, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(fingerprint, "Key generation should return a fingerprint.")
        self.assertIsInstance(fingerprint, str)
        self.assertTrue(len(fingerprint) > 10, "Fingerprint seems too short.") # Basic sanity check

        # Verify the key exists in our temporary keyring
        keys = self.gpg_obj_for_cleanup.list_keys(secret=True, keys=email)
        self.assertTrue(len(keys) > 0, "Key not found in temporary keyring after generation.")
        self.assertEqual(keys[0]['fingerprint'], fingerprint)
        print(f"Generated key with fingerprint: {fingerprint}")

    def test_02_encrypt_decrypt_successful(self):
        print("\nRunning test_02_encrypt_decrypt_successful...")
        name = "Test EncDec"
        email = "encdec@example.com"
        passphrase = "testencdecpass"
        original_data = "This is a secret message for testing encryption and decryption."

        # Generate a key pair for this test
        recipient_key_id = pgp_key_utils.generate_key_pair(name, email, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(recipient_key_id, "Failed to generate key for encryption/decryption test.")
        print(f"Generated key {recipient_key_id} for enc/dec test.")

        # Encrypt
        encrypted_data = pgp_key_utils.encrypt_data(original_data, recipient_key_id, **self.gpg_kwargs)
        self.assertIsNotNone(encrypted_data, "Encryption failed.")
        self.assertTrue("BEGIN PGP MESSAGE" in encrypted_data, "Encrypted data doesn't look like PGP block.")
        print("Data encrypted.")

        # Decrypt
        decrypted_data = pgp_key_utils.decrypt_data(encrypted_data, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(decrypted_data, "Decryption failed.")
        self.assertEqual(decrypted_data, original_data, "Decrypted data does not match original.")
        print("Data decrypted successfully and matches original.")

    def test_03_decrypt_wrong_passphrase(self):
        print("\nRunning test_03_decrypt_wrong_passphrase...")
        name = "Test WrongPass"
        email = "wrongpass@example.com"
        passphrase = "correctpass"
        wrong_passphrase = "incorrectpass"
        original_data = "Secret data for wrong passphrase test."

        recipient_key_id = pgp_key_utils.generate_key_pair(name, email, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(recipient_key_id, "Failed to generate key for wrong passphrase test.")
        print(f"Generated key {recipient_key_id} for wrong passphrase test.")

        encrypted_data = pgp_key_utils.encrypt_data(original_data, recipient_key_id, **self.gpg_kwargs)
        self.assertIsNotNone(encrypted_data, "Encryption failed for wrong passphrase test.")
        print("Data encrypted for wrong passphrase test.")

        # Attempt to decrypt with the wrong passphrase
        # We expect this to fail, so decrypted_data should be None (or handle error status)
        # The pgp_key_utils.decrypt_data prints errors and returns None on failure.
        decrypted_data = pgp_key_utils.decrypt_data(encrypted_data, wrong_passphrase, **self.gpg_kwargs)
        self.assertIsNone(decrypted_data, "Decryption should fail with wrong passphrase and return None.")
        print("Decryption correctly failed with wrong passphrase.")

    def test_04_encrypt_decrypt_empty_string(self):
        print("\nRunning test_04_encrypt_decrypt_empty_string...")
        name = "Test EmptyStr"
        email = "emptystr@example.com"
        passphrase = "testemptypass"
        original_data = "" # Empty string

        recipient_key_id = pgp_key_utils.generate_key_pair(name, email, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(recipient_key_id, "Failed to generate key for empty string test.")

        encrypted_data = pgp_key_utils.encrypt_data(original_data, recipient_key_id, **self.gpg_kwargs)
        self.assertIsNotNone(encrypted_data, "Encryption of empty string failed.")

        decrypted_data = pgp_key_utils.decrypt_data(encrypted_data, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(decrypted_data, "Decryption of empty string failed.")
        self.assertEqual(decrypted_data, original_data, "Decrypted empty string does not match original.")
        print("Empty string encrypted and decrypted successfully.")

    def test_05_encrypt_decrypt_large_string(self):
        print("\nRunning test_05_encrypt_decrypt_large_string...")
        name = "Test LargeStr"
        email = "largestr@example.com"
        passphrase = "testlargepass"
        original_data = "This is a large string. " * 1000 # Approx 25KB

        recipient_key_id = pgp_key_utils.generate_key_pair(name, email, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(recipient_key_id, "Failed to generate key for large string test.")

        encrypted_data = pgp_key_utils.encrypt_data(original_data, recipient_key_id, **self.gpg_kwargs)
        self.assertIsNotNone(encrypted_data, "Encryption of large string failed.")

        decrypted_data = pgp_key_utils.decrypt_data(encrypted_data, passphrase, **self.gpg_kwargs)
        self.assertIsNotNone(decrypted_data, "Decryption of large string failed.")
        self.assertEqual(decrypted_data, original_data, "Decrypted large string does not match original.")
        print("Large string encrypted and decrypted successfully.")

    def test_06_encrypt_non_existent_recipient(self):
        print("\nRunning test_06_encrypt_non_existent_recipient...")
        non_existent_key_id = "NONEXISTENTFINGERPRINT12345"
        original_data = "Data for non-existent recipient test."

        # encrypt_data should return None if recipient key is not found.
        encrypted_data = pgp_key_utils.encrypt_data(original_data, non_existent_key_id, **self.gpg_kwargs)
        self.assertIsNone(encrypted_data, "Encryption should fail for a non-existent recipient.")
        print("Encryption correctly failed for non-existent recipient.")

    # Optional: Test key deletion if needed for more granular cleanup,
    # but rmtree in tearDownClass should handle it for gnupghome.
    # def test_99_delete_test_keys(self):
    #     # This is an example if you needed to delete keys explicitly.
    #     # Be very careful with key deletion.
    #     keys_to_delete = ["keygen@example.com", "encdec@example.com", "wrongpass@example.com", "emptystr@example.com", "largestr@example.com"]
    #     for email_pattern in keys_to_delete:
    #         # Find all keys (public and secret) matching the email
    #         pub_keys = self.gpg_obj_for_cleanup.list_keys(keys=email_pattern)
    #         sec_keys = self.gpg_obj_for_cleanup.list_keys(secret=True, keys=email_pattern)

    #         for key in pub_keys + sec_keys:
    #             fingerprint = key['fingerprint']
    #             # It's safer to use delete_keys for secret keys and then public keys
    #             # Forcing deletion of secret keys first:
    #             if key['trust'] == '-' and key['type'] == 'sec': # Heuristic for secret key
    #                  self.gpg_obj_for_cleanup.delete_keys(fingerprint, secret=True) # Delete secret key
    #                  print(f"Attempted to delete secret key: {fingerprint}")
    #                  self.gpg_obj_for_cleanup.delete_keys(fingerprint) # Delete public key
    #                  print(f"Attempted to delete public key: {fingerprint}")
    #             else: # Public key or already deleted secret counterpart
    #                  self.gpg_obj_for_cleanup.delete_keys(fingerprint)
    #                  print(f"Attempted to delete public key: {fingerprint}")


if __name__ == "__main__":
    unittest.main()
