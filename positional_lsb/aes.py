from Crypto.Cipher import AES


class AEScipher:
    def __init__(self, aes_key: bytes, init_vector: bytes = b'\0' * 16):
        self.encrypter = AES.new(aes_key, AES.MODE_CFB, init_vector)
        self.decrypter = AES.new(aes_key, AES.MODE_CFB, init_vector)

    def encrypt(self, data: bytes) -> bytes:
        return self.encrypter.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.decrypter.decrypt(data)
