from Crypto.Cipher import AES, DES3


class AEScipher:
    def __init__(self, aes_key: bytes, init_vector: bytes = b'\0' * 16):
        self.encrypter = AES.new(aes_key, AES.MODE_CFB, init_vector)
        self.decrypter = AES.new(aes_key, AES.MODE_CFB, init_vector)

    def encrypt(self, data: bytes) -> bytes:
        return self.encrypter.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.decrypter.decrypt(data)


class DES3cipher:
    def __init__(self, sha3_hash: bytes):
        key = DES3.adjust_key_parity(sha3_hash[:24])
        self.cipher = DES3.new(key, DES3.MODE_CFB, sha3_hash[24:])

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)
