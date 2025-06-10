import pgp_key_utils

def main():
    # 1. Define example user details and a sample message.
    user_name = "Alice Wonderland"
    user_email = "alice@wonderland.io"
    user_passphrase = "verysecurepassword123"
    original_message = "Hello Bob! This is a top secret message."

    print("--- PGP Encryption/Decryption Demo ---")

    # 2. Call generate_key_pair to create or retrieve a PGP key.
    print("\nStep 1: Generate/Retrieve PGP Key Pair")
    # The function now returns the fingerprint (str) or None
    key_id = pgp_key_utils.generate_key_pair(user_name, user_email, user_passphrase)

    if not key_id:
        print("Failed to generate or retrieve key. Exiting.")
        return

    print(f"Using key with ID (Fingerprint): {key_id}")

    # 3. Call encrypt_data to encrypt the sample message.
    print("\nStep 2: Encrypt Message")
    encrypted_message = pgp_key_utils.encrypt_data(original_message, key_id)

    if not encrypted_message:
        print("Failed to encrypt message. Exiting.")
        return

    print("Encrypted Message:")
    print(encrypted_message)

    # 4. Call decrypt_data to decrypt the encrypted message.
    print("\nStep 3: Decrypt Message")
    decrypted_message = pgp_key_utils.decrypt_data(encrypted_message, user_passphrase)

    if not decrypted_message:
        print("Failed to decrypt message. Exiting.")
        return

    print("Decrypted Message:")
    print(decrypted_message)

    # 5. Compare the decrypted message with the original sample message.
    print("\nStep 4: Verification")
    if decrypted_message == original_message:
        print("SUCCESS: Decrypted message matches the original message!")
    else:
        print("FAILURE: Decrypted message does NOT match the original message.")
        print(f"Original: '{original_message}'")
        print(f"Decrypted: '{decrypted_message}'")

if __name__ == "__main__":
    main()
