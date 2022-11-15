from tempfile import TemporaryFile
from hashlib import sha3_256
from math import ceil

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes


def normalize_data(data: bytes) -> bytes:
    pad_lenth = ceil(len(data) / 8) * 8 - len(data)
    with TemporaryFile() as tmp_file:
        tmp_file.write(data)
        tmp_file.write(b'\x00' * pad_lenth)
        tmp_file.seek(0)
        normalized_data = tmp_file.read()
        tmp_file.close()
    return normalized_data


text = 'Positional LSB - is cool!'
key = DES3.adjust_key_parity(sha3_256(''.encode('utf-8')).digest()[:24])
data_bytes = normalize_data(text.encode('utf-8'))

cipher = DES3.new(key, DES3.MODE_CFB)
msg = cipher.iv + cipher.encrypt(data_bytes)
print(text)
print(key)
print(cipher.iv)
print(msg.hex())
cipher = DES3.new(key, DES3.MODE_CFB)
msg = cipher.decrypt(msg)[8:].decode('UTF-8')
print(msg)
