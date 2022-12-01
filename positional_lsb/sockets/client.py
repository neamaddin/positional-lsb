import socket
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

from positional_lsb.aes import AEScipher


class Client:
    def __init__(self, ip_address, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip_address = ip_address
        self.port = port
        self.aes_key = get_random_bytes(16)
        self.aes_cipher = AEScipher(self.aes_key)

    def _reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode('utf-8'))

    def _relaible_recieve(self):
        json_data = ''
        while True:
            json_data += self.connection.recv(1024).decode('utf-8')
            try:
                return json.loads(json_data)
            except ValueError:
                continue

    def _aes_key_ship_status(self):
        status = self._relaible_recieve()
        if status == '200: OK':
            print('[+] Ключ AES был успешно доставлен')
        else:
            print('[-] Что-то пошло не так')
            self.connection.close()

    def _establish_secure_connection(self):
        self.connection.connect((self.ip_address, self.port))
        self._reliable_send('Get RSA public key')
        n_value, e_value = self._relaible_recieve()
        public_key = RSA.construct((n_value, e_value))
        print(f'[+] Публичный ключ был успешно получен: {public_key}')
        cipher = PKCS1_OAEP.new(public_key)
        ciphered_key = cipher.encrypt(self.aes_key).hex()
        self._reliable_send({'aes_key': ciphered_key})
        self._aes_key_ship_status()

    def get_image(self):
        self._establish_secure_connection()
        self._reliable_send(self.aes_cipher.encrypt(b'Get image').hex())
        response_data_raw = self._relaible_recieve()
        print(self.aes_cipher.decrypt(bytes.fromhex(response_data_raw)))

if __name__ == '__main__':
    sender = Client('192.168.1.2', 4444)
    sender.get_image()
