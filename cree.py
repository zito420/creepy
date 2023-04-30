import os
import glob
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import getpass

def prompt_for_password():
    password = getpass.getpass("Enter your secure password: ")
    return password.encode()

PASSWORD = prompt_for_password()

def generate_key(salt):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(PASSWORD)
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path):
    salt = os.urandom(16)
    key = generate_key(salt)
    cipher = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted_data = cipher.encrypt(data)
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(salt + encrypted_data)
    os.remove(file_path)
    return encrypted_file_path

def decrypt_file(file_path):
    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
    salt = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    key = generate_key(salt)
    cipher = Fernet(key)
    
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except InvalidToken:
        print("Authentication error. Try again.")
        return None

    original_file_path = file_path[:-4]
    with open(original_file_path, "wb") as original_file:
        original_file.write(decrypted_data)
    os.remove(file_path)
    return original_file_path


def main():
    print("1. Encrypt files")
    print("2. Decrypt files")
    choice = int(input("Choose an option (1 or 2): "))

    if choice == 1:
        file_pattern = input("Enter the file pattern (e.g., *.txt): ")
        files_to_encrypt = glob.glob(file_pattern)
        for file_path in files_to_encrypt:
            encrypted_file_path = encrypt_file(file_path)
            print(f"Encrypted {file_path} -> {encrypted_file_path}")
    elif choice == 2:
        file_pattern = input("Enter the encrypted file pattern (e.g., *.enc): ")
        files_to_decrypt = glob.glob(file_pattern)
        for file_path in files_to_decrypt:
            decrypted_file_path = decrypt_file(file_path)
            print(f"Decrypted {file_path} -> {decrypted_file_path}")
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
