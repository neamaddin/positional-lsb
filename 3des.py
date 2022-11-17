from hashlib import sha3_256

from Crypto.Cipher import DES3

# Текст для шифрования
text = 'Positional LSB - is cool!'
# Задание ключа
key = DES3.adjust_key_parity(sha3_256(b'').digest()[:24]) 

# Шифрование информации
cipher = DES3.new(key, DES3.MODE_CFB)
msg = cipher.iv + cipher.encrypt(text.encode('utf-8'))

# Дешифрование информации
cipher = DES3.new(key, DES3.MODE_CFB)
msg = cipher.decrypt(msg)[8:].decode('UTF-8')
