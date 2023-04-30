# Cree.py: File Encryption and Decryption Tool

This is a simple CLI tool for encrypting and decrypting files using the Fernet symmetric key encryption provided by the `cryptography` library. It uses a password-based key derivation function ([PBKDF2HMAC](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)) with SHA-256 and a random salt to generate the encryption key.

## Installation

1. Make sure you have Python 3.6 or higher installed on your system. You can check your Python version running `python --version`

2. Install the required dependencies:

    `pip install cryptography`

## Usage

1. Clone this repository or download the `cree.py`file.

2. Move the files you want to encrypt or decrypt into the same folder.

3. Run Creepy:

     `python cree.py`

4. Follow the instructions. You will be prompted to enter your secure password for both encryption and decryption processes.

## Notes

- When a file is encrypted or decrypted, the original file will be deleted.
- The salt used for key derivation is stored within the encrypted file.

## Security

EDUCATIONAL AND PERSONAL USE ONLY! For professional or high-security use cases, consider using a specialized encryption tool, like VeraCrypt.

## License

This project is released under the [MIT License](LICENSE).
