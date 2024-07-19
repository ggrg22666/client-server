from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def encrypt_message(message, session_key):
    cipher = Cipher(algorithms.AES(session_key), modes.ECB())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message

def decrypt_message(encrypted_message, session_key):
    cipher = Cipher(algorithms.AES(session_key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode('utf-8')
