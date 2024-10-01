class EncryptedLogin:
    def __init__(self, website, email, password, salt):
        self.website = website
        self.email = email
        self.password = password
        self.salt = salt
