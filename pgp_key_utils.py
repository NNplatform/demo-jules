import gnupg

def generate_key_pair(name, email, passphrase, **kwargs):
    """
    Generates a new PGP key pair.

    Args:
        name: The name associated with the key.
        email: The email associated with the key.
        passphrase: The passphrase for the key.
    """
    gpg = gnupg.GPG(**kwargs) # Pass all kwargs, including gnupghome if present

    # Check if the key already exists
    existing_keys = gpg.list_keys(secret=True, keys=email)
    if existing_keys:
        fingerprint = existing_keys[0]['fingerprint']
        print(f"Using existing key for {email} with fingerprint: {fingerprint}")
        return fingerprint

    # If not, generate a new key
    print(f"Generating new key for {name} <{email}>...")
    key_input_parameters = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real=name,
        name_email=email,
        passphrase=passphrase
    )
    key = gpg.gen_key(key_input_parameters)
    if key:
        print(f"Key generated successfully!")
        print(f"Fingerprint: {key.fingerprint}")
        return key.fingerprint
    else:
        print("Error generating key.")
        return None

def decrypt_data(encrypted_data_str, passphrase, **kwargs):
    """
    Decrypts PGP encrypted data.

    Args:
        encrypted_data_str: The encrypted data string.
        passphrase: The passphrase for the private key.

    Returns:
        The decrypted data as a string, or None if decryption fails.
    """
    gpg = gnupg.GPG(**kwargs) # Pass all kwargs
    # The encrypted_data_str needs to be bytes for gpg.decrypt
    # If it's a string that looks like PGP block, gnupg should handle it.
    decrypted_data = gpg.decrypt(encrypted_data_str, passphrase=passphrase)

    if decrypted_data.ok:
        return str(decrypted_data)
    else:
        print(f"Error decrypting data: {decrypted_data.status}")
        if decrypted_data.stderr:
            print(f"GPG Errors: {decrypted_data.stderr}")
        # More specific error checking based on status or stderr
        status_lower = str(decrypted_data.status).lower()
        stderr_lower = str(decrypted_data.stderr).lower()
        if "bad passphrase" in status_lower or "bad passphrase" in stderr_lower:
            print("Decryption failed due to incorrect passphrase.")
        elif "decryption failed" in status_lower or "no secret key" in stderr_lower:
            print("Decryption failed. Data might be corrupted or not encrypted for any available secret key, or the secret key is missing.")
        return None

# Moved the function definition above the if __name__ == '__main__': block
def encrypt_data(data, recipient_key_id, **kwargs):
    """
    Encrypts data using the recipient's public PGP key.

    Args:
        data: The data to encrypt (string).
        recipient_key_id: The fingerprint or email of the recipient's key.

    Returns:
        The encrypted data as a string, or None if encryption fails.
    """
    gpg = gnupg.GPG(**kwargs) # Pass all kwargs
    # Ensure the recipient key is available
    public_keys = gpg.list_keys() # This will use the gpg object initialized with kwargs
    recipient_found = any(key['fingerprint'] == recipient_key_id or
                          any(uid.startswith(f"{recipient_key_id} <") or f" <{recipient_key_id}>" in uid for uid in key.get('uids', []))
                          for key in public_keys)

    if not recipient_found:
        print(f"Error: Recipient key {recipient_key_id} not found.")
        # Attempt to import the key if it's a known fingerprint but not in the keyring
        # This part might need adjustment based on how keys are managed/retrieved in a real scenario
        # For now, we'll just error out if not immediately found.
        return None

    encrypted_data = gpg.encrypt(data, recipient_key_id, always_trust=True) # always_trust=True for testing if key is not fully trusted
    if encrypted_data.ok:
        return str(encrypted_data)
    else:
        print(f"Error encrypting data: {encrypted_data.status}")
        if encrypted_data.stderr:
            print(f"GPG Errors: {encrypted_data.stderr}")
        return None

if __name__ == '__main__':
    # Example usage (demonstrating the functions)
    user_name = "Test User Main"
    user_email = "testmain@example.com"
    user_passphrase = "testmainpassphrase"
    original_message = "This is a secret message from main.py!"

    print("--- Key Generation/Retrieval ---")
    key_fingerprint = generate_key_pair(user_name, user_email, user_passphrase)

    if key_fingerprint:
        print(f"\n--- Encryption (using key: {key_fingerprint}) ---")
        data_to_encrypt = original_message
        encrypted_output = encrypt_data(data_to_encrypt, key_fingerprint) # Use email or fingerprint
        if encrypted_output:
            print("\nEncrypted Data:")
            print(encrypted_output)

            print(f"\n--- Decryption (using passphrase: '{user_passphrase}') ---")
            decrypted_output = decrypt_data(encrypted_output, user_passphrase)
            if decrypted_output:
                print("\nDecrypted Data:")
                print(decrypted_output)

                if decrypted_output == original_message:
                    print("\nSUCCESS: Decrypted message matches the original.")
                else:
                    print("\nFAILURE: Decrypted message does NOT match the original.")
            else:
                print("\nDecryption failed.")
        else:
            print("\nEncryption failed.")
    else:
        print("\nKey generation/retrieval failed. Cannot proceed with encryption/decryption.")
