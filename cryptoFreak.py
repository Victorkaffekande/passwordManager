import base64
import os
from argon2 import PasswordHasher, Type, hash_password_raw
from cryptography.fernet import Fernet, InvalidToken
from loginRepo import *


ph = PasswordHasher(time_cost=4, memory_cost=65536, parallelism=2, hash_len=32)

def set_master_password(master_password):
    hashedPass = ph.hash(master_password)
    save_hashed_master_password(hashedPass)


def verify_master_password(master_password):
    hashedPw = get_hashed_master_password()
    try:
        return ph.verify(hashedPw, master_password)
    except:
        return False


def derive_key_from_master_password(password: str, salt: bytes) -> bytes:
    key = hash_password_raw(password.encode(),salt,time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, type=Type.I) 
    key64 = base64.urlsafe_b64encode(key)
    print("key64",key64, "password", password, "salt", salt)
    return key64


def encrypt_save_login_detail(website: str, email: str, password: str, master_password: str):
    # Generate a random salt for each message
    salt = os.urandom(16)
    key = derive_key_from_master_password(master_password, salt)
    f = Fernet(key)
    save_login(f.encrypt(website.encode()), f.encrypt(email.encode()), f.encrypt(password.encode()), salt)


def decrypt_login_details(master_password) -> list:
    decryptedLogins = []
    for login in get_logins():
        dLogin = {
            'email': decrypt_message(login.email, login.salt, master_password),
            'website': decrypt_message(login.website, login.salt, master_password),
            'password': decrypt_message(login.password, login.salt, master_password),
        }
        decryptedLogins.append(dLogin)
    return decryptedLogins


def decrypt_message(encrypted_message: bytes, salt: bytes, master_password: str) -> str:
    key = derive_key_from_master_password(master_password, salt) 
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode('utf-8')
        return decrypted_message
    except InvalidToken:
        return "Invalid token! Decryption failed."
