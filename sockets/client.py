from base64 import b64encode
from hashlib import md5
import socket
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes


class Client:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.port = port
        self.aes_key = get_random_bytes(16)

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode('utf-8'))

    def relaible_recieve(self):
        json_data = ''
        while True:
            json_data += self.connection.recv(1024).decode('utf-8')
            try:
                return json.loads(json_data)
            except ValueError:
                continue

    def _aes_key_ship_status(self):
        status = self.relaible_recieve()
        if status == '200: OK':
            print('[+] Ключ AES был успешно доставлен')
        else:
            print('[-] Что-то пошло не так')
            self.connection.close()

    def run(self):
        self.connection.connect((self.ip, self.port))
        self.reliable_send('Get RSA public key')
        n_value, e_value = self.relaible_recieve()
        public_key = RSA.construct((n_value, e_value))
        print(f'[+] Публичный ключ был успешно получен: {public_key}')
        cipher = PKCS1_OAEP.new(public_key)
        ciphered_key = cipher.encrypt(self.aes_key).hex()
        self.reliable_send({'aes_key': ciphered_key})
        self._aes_key_ship_status()
        cipher = AES.new(self.aes_key, AES.MODE_CFB)
        self.reliable_send({'init': cipher.encrypt(b'initial_value_aes').hex(),})
        while True:
            text = input('Введите текст: ')
            encrypted_text = cipher.encrypt(text.encode('utf-8'))
            self.reliable_send({'text': encrypted_text.hex(),})

sender = Client('192.168.1.2', 4444)
sender.run()
