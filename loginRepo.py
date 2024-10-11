from __future__ import annotations

import sqlite3
import enteties
from enteties.encrypedWebsite import EncryptedWebsite
from enteties.encryptedLogin import EncryptedLogin


def get_connection():
    return sqlite3.connect('db.db')


def create_database():
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute("DROP TABLE IF EXISTS logins")
        cursor.execute("DROP TABLE IF EXISTS masterPass")
        cursor.execute("CREATE TABLE IF NOT EXISTS masterPass(hashedMasterPassword)")
        cursor.execute(
            "CREATE TABLE logins(id INTEGER primary key AUTOINCREMENT , website TEXT, email TEXT, password TEXT, salt TEXT) ")


def save_hashed_master_password(hashedMasterPassword):
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM masterPass")  # Clear all data so only one pasword exist :)
        cursor.execute("INSERT INTO masterPass (hashedMasterPassword) VALUES (?)", (hashedMasterPassword,))
        connection.commit()


def get_hashed_master_password():
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM masterPass")
        rows = cursor.fetchall()[0]
        return rows[0]


def save_login(website, email, encrypted_password, salt):
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO logins (website, email, password, salt) VALUES (?, ?, ?, ?)",
                       (website, email, encrypted_password, salt))
        newestId = cursor.lastrowid
        connection.commit()
        return newestId


def delete_login(id):
    with get_connection() as connection:
        cursor = connection.cursor()
        query = "DELETE FROM logins WHERE id = ?"
        cursor.execute(query, (id,))
        connection.commit()


def get_encrypted_login(id) -> ValueError | EncryptedLogin:
    with get_connection() as connection:
        cursor = connection.cursor()
        query = "SELECT * FROM logins where id == ?"
        cursor.execute(query, (id,))
        r = cursor.fetchone()
        if r is None:
            return ValueError("not found")
        encryptedLogin = EncryptedLogin(r[0], r[1], r[2], r[3], r[4])
        return encryptedLogin


def get_encrypted_websites():
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT id,website,salt FROM logins")
        rows = cursor.fetchall()
        list = []
        for r in rows:
            eW = EncryptedWebsite(r[0], r[1], r[2])
            list.append(eW)
        return list
