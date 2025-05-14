from flask import Flask, render_template, request, send_file, abort
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import os
from werkzeug.utils import secure_filename
import base64  # Import base64 for handling image data

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

def encrypt_file(file_path, key, cipher_type='des'):
    """Encrypts the file using DES or AES algorithm.

    Args:
        file_path (str): Path to the file to be encrypted.
        key (str): Encryption key (8 bytes for DES, 16/24/32 for AES).
        cipher_type (str, optional): 'des' or 'aes'. Defaults to 'des'.

    Returns:
        str: Path to the encrypted file.

    Raises:
        ValueError: If the key or cipher_type is invalid.
        Exception: For other errors during encryption.
    """
    if cipher_type not in ('des', 'aes'):
        raise ValueError("Invalid cipher type. Must be 'des' or 'aes'")
    if cipher_type == 'des' and len(key) != 8:
        raise ValueError("Key must be 8 bytes long for DES")
    if cipher_type == 'aes' and len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long for AES")

    try:
        with open(file_path, 'rb') as infile:
            plaintext = infile.read()

        if cipher_type == 'des':
            cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
            padded_plaintext = pad(plaintext, DES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
        elif cipher_type == 'aes':
            cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)

        encrypted_filename = secure_filename(os.path.basename(file_path)) + ".enc"
        encrypted_filepath = os.path.join(PROCESSED_FOLDER, encrypted_filename)
        with open(encrypted_filepath, 'wb') as outfile:
            outfile.write(ciphertext)
        return encrypted_filepath
    except Exception as e:
        raise Exception(f"Encryption failed: {e}")


def decrypt_file(file_path, key, cipher_type='des'):
    """Decrypts the file using DES or AES algorithm.

    Args:
        file_path (str): Path to the file to be decrypted.
        key (str): Decryption key (8 bytes for DES, 16/24/32 for AES).
        cipher_type (str, optional): 'des' or 'aes'. Defaults to 'des'.

    Returns:
        str: Path to the decrypted file.

    Raises:
        ValueError: If the key or cipher_type is invalid.
        Exception: For other errors during decryption.
    """
    if cipher_type not in ('des', 'aes'):
        raise ValueError("Invalid cipher type. Must be 'des' or 'aes'")
    if cipher_type == 'des' and len(key) != 8:
        raise ValueError("Key must be 8 bytes long for DES")
    if cipher_type == 'aes' and len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long for AES")

    try:
        with open(file_path, 'rb') as infile:
            ciphertext = infile.read()

        if cipher_type == 'des':
            cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, DES.block_size)
        elif cipher_type == 'aes':
            cipher = AES.new(key.encode('utf-8'), DES.MODE_ECB)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)

        decrypted_filename = secure_filename(os.path.basename(file_path))
        if decrypted_filename.endswith(".enc"):
            decrypted_filename = decrypted_filename[:-4]
        decrypted_filepath = os.path.join(PROCESSED_FOLDER, decrypted_filename)
        with open(decrypted_filepath, 'wb') as outfile:
            outfile.write(plaintext)
        return decrypted_filepath
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")


@app.route('/', methods=['GET'])
def index():
    """Displays the main page (index.html)."""
    return render_template('index.html')


@app.route('/', methods=['POST'])
def process_request():
    """Handles file encryption/decryption requests, including images.

    Validates the key, saves the uploaded file, performs the
    requested action (encryption/decryption), and sends the
    processed file back to the user.  Handles images and other file types.
    """
    if 'file' not in request.files:
        abort(400, "No file provided")
    file = request.files['file']
    key = request.form['key']
    action = request.form['action']
    cipher_type = request.form.get('cipher_type', 'des') # Default to DES

    if not file or file.filename == '':
        abort(400, "Please select a file to process")

    # Key length validation is now handled by encrypt/decrypt_file based on cipher_type
    if cipher_type not in ['des', 'aes']:
        abort(400, "Invalid cipher type.  Must be 'des' or 'aes'")

    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        if action == 'encrypt':
            output_path = encrypt_file(file_path, key, cipher_type)
        elif action == 'decrypt':
            output_path = decrypt_file(file_path, key, cipher_type)
        else:
            abort(400, "Invalid action.  Must be 'encrypt' or 'decrypt'")

        return send_file(output_path, as_attachment=True)

    except Exception as e:
        print(f"Error processing file: {e}")
        abort(500, str(e))

if __name__ == '__main__':
    app.run(debug=True)
