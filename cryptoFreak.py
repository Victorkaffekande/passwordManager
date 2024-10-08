import base64
import os
from argon2 import PasswordHasher, Type, hash_password_raw
from cryptography.fernet import Fernet, InvalidToken

from enteties.login import Login
from enteties.websiteDTO import WebsiteDTO
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
    key = hash_password_raw(password.encode(), salt, time_cost=4, memory_cost=65536, parallelism=2, hash_len=32,
                            type=Type.I)
    key64 = base64.urlsafe_b64encode(key)
    return key64


def encrypt_save_login_detail(login: Login, master_password: str):
    # Generate a random salt for each message
    salt = os.urandom(16)
    key = derive_key_from_master_password(master_password, salt)
    f = Fernet(key)
    save_login(f.encrypt(login.website.encode()), f.encrypt(login.email.encode()), f.encrypt(login.password.encode()),
               salt)


def decrypt_login_details(master_password) -> list:
    decryptedLogins = []

    for encryptedLogin in get_encrypted_logins():
        key = derive_key_from_master_password(master_password, encryptedLogin.salt)
        login = Login(encryptedLogin.id, decrypt_message(encryptedLogin.website, key),
                      decrypt_message(encryptedLogin.email, key), decrypt_message(encryptedLogin.password, key))

        decryptedLogins.append(login)
    return decryptedLogins


def get_decrypted_login(id, master_password):
    encryptedLogin = get_encrypted_login(id)
    key = derive_key_from_master_password(master_password, encryptedLogin.salt)
    return Login(encryptedLogin.id,
                 decrypt_message(encryptedLogin.website, key),
                 decrypt_message(encryptedLogin.email, key),
                 decrypt_message(encryptedLogin.password, key))


def get_decrypted_websites(master_password) -> list:
    encryptedWebsite = get_encrypted_websites()
    decryptedWebsites = []
    for encryptedWebsite in encryptedWebsite:
        key = derive_key_from_master_password(master_password, encryptedWebsite.salt)
        websiteDto = WebsiteDTO(encryptedWebsite.id, decrypt_message(encryptedWebsite.website, key))
        decryptedWebsites.append(websiteDto)
    return decryptedWebsites


def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode('utf-8')
        return decrypted_message
    except InvalidToken:
        return "Invalid token! Decryption failed."
