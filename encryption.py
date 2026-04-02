from cryptography.fernet import Fernet

def encrypt_data(data):
    key = Fernet.generate_key()
    cipher = Fernet(key)

    encrypted = cipher.encrypt(data.encode())
    return encrypted