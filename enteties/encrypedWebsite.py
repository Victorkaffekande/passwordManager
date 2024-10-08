class EncryptedWebsite:
    def __init__(self, id, website, salt):
        self.id = id
        self.website = website
        self.salt = salt