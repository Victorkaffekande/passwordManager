import sqlite3
import enteties
from enteties.encryptedLogin import EncryptedLogin


def get_connection():
    return sqlite3.connect('db.db')


def create_database():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS masterPass(hashedMasterPassword)")
    cursor.execute("CREATE TABLE IF NOT EXISTS logins(website TEXT, email TEXT, password TEXT, salt TEXT)")
    connection.close()


def save_hashed_master_password(hashedMasterPassword):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM masterPass")  # Clear all data so only one pasword exist :)
    cursor.execute("INSERT INTO masterPass (hashedMasterPassword) VALUES (?)", (hashedMasterPassword,))
    connection.commit()
    connection.close()


def get_hashed_master_password():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM masterPass")
    rows = cursor.fetchall()[0]
    connection.close()
    return rows[0]


def save_login(website, email, encrypted_password, salt):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO logins (website, email, password, salt) VALUES (?, ?, ?, ?)",
                   (website, email, encrypted_password, salt))
    connection.commit()
    connection.close()


def get_logins() -> list[EncryptedLogin]:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM logins")
    rows = cursor.fetchall()
    list = []
    for r in rows:
        eL = EncryptedLogin(r[0], r[1], r[2], r[3])
        list.append(eL)
    return list
