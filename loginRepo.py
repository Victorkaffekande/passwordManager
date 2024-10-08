import sqlite3
import enteties
from enteties.encrypedWebsite import EncryptedWebsite
from enteties.encryptedLogin import EncryptedLogin


def get_connection():
    return sqlite3.connect('db.db')


def create_database():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS masterPass(hashedMasterPassword)")
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS logins(id INTEGER primary key AUTOINCREMENT , website TEXT, email TEXT, password TEXT, salt TEXT) ")
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


def get_encrypted_logins() -> list[EncryptedLogin]:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM logins")
    rows = cursor.fetchall()
    list = []
    for r in rows:
        eL = EncryptedLogin(r[0], r[1], r[2], r[3], r[4])
        list.append(eL)
    connection.close()
    return list


def get_encrypted_login(id) -> EncryptedLogin:
    connection = get_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM logins where id == ?"
    cursor.execute(query, (id,))
    r = cursor.fetchone()
    encryptedLogin = EncryptedLogin(r[0], r[1], r[2], r[3], r[4])
    connection.close()
    return encryptedLogin


def get_encrypted_websites():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id,website,salt FROM logins")
    rows = cursor.fetchall()
    list = []
    for r in rows:
        eW = EncryptedWebsite(r[0], r[1], r[2])
        list.append(eW)
    connection.close()
    return list
