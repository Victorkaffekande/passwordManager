﻿class EncryptedLogin:
    def __init__(self,id, website, email, password, salt):
        self.id = id
        self.website = website
        self.email = email
        self.password = password
        self.salt = salt
