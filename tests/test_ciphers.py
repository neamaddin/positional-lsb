from hashlib import sha3_256

import pytest

from positional_lsb.ciphers import AEScipher, DES3cipher
from positional_lsb.exceptions import LengthError


SHA3_256_DEFAULT = sha3_256(b'').digest()
AES_ENCRYPTED_DATA = b'\xa64kSn'
DES3_ENCRYPTED_DATA = b'\xb3\x14\xf7N\x98'


class TestAEScipher:
    aes = AEScipher(SHA3_256_DEFAULT[:16])

    @pytest.mark.parametrize(
        ('key', 'iv'), [
            ('', None),
            (1, None),
            (True, None),
            (1.5, None),
            (b'\0' * 16, ''),
            (b'\0' * 16, 1),
            (b'\0' * 16, True),
            (b'\0' * 16, 1.5)
        ]
    )
    def test_init_type_error(self, key, iv):
        with pytest.raises(TypeError):
            if iv is None:
                AEScipher(key)
            else:
                AEScipher(key, iv)

    def test_init_length_normal(self):
        assert isinstance(AEScipher(b'\0' * 16), AEScipher)
        assert isinstance(AEScipher(b'\0' * 17), AEScipher)
        assert isinstance(AEScipher(b'\0' * 16, b'\0' * 16), AEScipher)
        assert isinstance(AEScipher(b'\0' * 17, b'\0' * 17), AEScipher)

    def test_init_length_error(self):
        with pytest.raises(LengthError):
            AEScipher(b'\0' * 15)

    def test_encrypt(self):
        assert self.aes.encrypt(b'Hello') == AES_ENCRYPTED_DATA

    @pytest.mark.parametrize('data', ['', 1, True, 1.5])
    def test_encrypt_errors(self, data):
        with pytest.raises(TypeError):
            self.aes.encrypt(data)

    def test_decrypt(self):
        assert self.aes.decrypt(AES_ENCRYPTED_DATA) == b'Hello'

    @pytest.mark.parametrize('data', ['', 1, True, 1.5])
    def test_decrypt_errors(self, data):
        with pytest.raises(TypeError):
            self.aes.decrypt(data)


class TestDES3cipher:
    def test_encrypt(self):
        des3 = DES3cipher(SHA3_256_DEFAULT)
        assert des3._encrypt(b'Hello') == DES3_ENCRYPTED_DATA

    def test_decrypt(self):
        des3 = DES3cipher(SHA3_256_DEFAULT)
        assert des3._decrypt(DES3_ENCRYPTED_DATA) == b'Hello'
