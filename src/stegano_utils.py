import cv2
import numpy as np
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate a 256-bit AES key from the password
def derive_key(password: str, salt: bytes = b'steganography_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased for better security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt message using AES-256-GCM
def encrypt_message(message: str, password: str):
    key = derive_key(password)
    iv = os.urandom(12)  # 12-byte IV for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + encrypted_msg).decode()

# Decrypt message using AES-256-GCM
def decrypt_message(encrypted_msg: str, password: str):
    try:
        key = derive_key(password)
        encrypted_data = base64.b64decode(encrypted_msg)
        iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except:
        return "⚠️ Incorrect Password or Corrupt Data!"

# Encode encrypted text into an image (LSB Steganography)
def encode_image(image_path, encrypted_message):
    img = cv2.imread(image_path)
    encrypted_message += "####"  # End delimiter
    binary_msg = ''.join(format(ord(ch), '08b') for ch in encrypted_message)

    data_index = 0
    msg_length = len(binary_msg)

    for row in img:
        for pixel in row:
            for channel in range(3):
                if data_index < msg_length:
                    pixel[channel] = (pixel[channel] & 0xFE) | int(binary_msg[data_index])
                    data_index += 1

    encoded_image_path = "images/encoded_image.png"
    cv2.imwrite(encoded_image_path, img)
    return encoded_image_path

# Decode hidden message from an image
def decode_image(image_path):
    img = cv2.imread(image_path)
    binary_msg = ""

    for row in img:
        for pixel in row:
            for channel in range(3):
                binary_msg += str(pixel[channel] & 1)

    all_bytes = [binary_msg[i:i+8] for i in range(0, len(binary_msg), 8)]
    decoded_msg = "".join([chr(int(byte, 2)) for byte in all_bytes])

    return decoded_msg.split("####")[0]  # Extract the message
