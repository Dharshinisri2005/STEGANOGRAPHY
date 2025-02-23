from stegano_utils import decode_image, decrypt_message

image_path = input("Enter the path to the encoded image: ")
password = input("Enter the password: ")

hidden_encrypted_message = decode_image(image_path)
original_message = decrypt_message(hidden_encrypted_message, password)

print(f"🔓 Decoded Message: {original_message}")
