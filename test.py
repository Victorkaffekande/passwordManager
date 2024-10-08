﻿from loginRepo import create_database
from cryptoFreak import *


def main():
    create_database()
    set_master_password("1")

    masterPass = input("Master password: ")
    if not verify_master_password(masterPass):
        print("Wrong password byyeeee")
        return

    while True:
        choice = input("1. Save Login\n2. View Logins\n3. Exit\nChoose an option: ")
        if choice == "1":
            website = input("Website: ")
            email = input("Username: ")
            password = input("Password: ")
            login = Login(website, email, password)
            encrypt_save_login_detail(login, masterPass)
        elif choice == "2":
            for l in decrypt_login_details(masterPass):
                print(l.id)
        elif choice == "3":
            print("quitting")
            break


main()