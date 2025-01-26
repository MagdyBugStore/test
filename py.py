import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Generate a random key using PBKDF2
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt the contents of a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Pad the data to make it a multiple of block size (AES block size is 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Encrypt the data using AES CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV and the encrypted data
    return iv + encrypted_data

# Decrypt the contents of a file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Extract the salt (first 16 bytes) and the encrypted data (rest of the bytes)
    salt = data[:16]
    encrypted_data = data[16:]

    # Derive the key from the password and salt
    key = generate_key(key, salt)

    # Extract the IV (first 16 bytes of the encrypted data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    # Decrypt the data using AES CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

# Encrypt all files in the given directory and its subdirectories
def encrypt_directory(directory_path, password):
    # Generate a salt (used to derive the key)
    salt = os.urandom(16)
    key = generate_key(password, salt)

    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            encrypted_data = encrypt_file(file_path, key)
            # Save the encrypted file (with .rcm extension)
            encrypted_file_path = file_path + ".rcm"
            with open(encrypted_file_path, 'wb') as enc_file:
                enc_file.write(salt + encrypted_data)  # Store salt along with encrypted data
            print(f"Encrypted: {file_path} -> {encrypted_file_path}")
            os.remove(file_path)  # Delete the original file after encryption
            print(f"Deleted original file: {file_path}")

# Decrypt all encrypted files in the given directory and its subdirectories
def decrypt_directory(directory_path, password):
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if file_path.endswith('.rcm'):
                decrypted_data = decrypt_file(file_path, password)
                # Save the decrypted file (removing the .rcm extension)
                decrypted_file_path = file_path[:-4]  # Remove .rcm extension
                with open(decrypted_file_path, 'wb') as dec_file:
                    dec_file.write(decrypted_data)
                print(f"Decrypted: {file_path} -> {decrypted_file_path}")
                os.remove(file_path)  # Delete the encrypted file after decryption
                print(f"Deleted encrypted file: {file_path}")

# Example usage:
# Get user input for encryption or decryption choice
user_input = input("Enter 1 to encrypt or 2 to decrypt: ")

# Get user input for the directory path
directory_path = input("Enter the path to the directory: ")

# Get user input for the password
password = input("Enter your password: ")

# Make sure the user input is numeric
if user_input == '1':
    encrypt_directory(directory_path, password)
elif user_input == '2':
    decrypt_directory(directory_path, password)
else:
    print("Invalid input. Please enter 1 to encrypt or 2 to decrypt.")
