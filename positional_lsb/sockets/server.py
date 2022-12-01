import logging
import socket
import json
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from positional_lsb.pystego import PositionalLSBImage
from positional_lsb.aes import AEScipher


logging.basicConfig(level=logging.INFO, filename='server.log', filemode='a',
                    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))


class Server:
    def __init__(self, ip_address, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip_address, port))
        listener.listen(0)
        self.aes_cipher: AEScipher
        self.private_key = RSA.generate(3072)
        self.public_key = self.private_key.public_key()
        logging.info('[+] Ключи были успешно сгенирированны: %s, %s',
                     self.public_key, self.private_key)
        logging.info('[+] Ожидание входяших подключений')
        self.connection, address = listener.accept()
        logging.info('[+] Установлено соединение с клиентом %s', address)

    def close_socket(self) -> None:
        self.connection.close()
        logging.info('[-] Сокет был успешно закрыт')

    def _send_rsa_pubkey(self) -> None:
        logging.info('[+] Запрошен публичный ключ (RSA)')
        pubkey = [self.public_key.n, self.public_key.e]
        self._reliable_send(pubkey)
        logging.info('[+] Публичный ключ RSA был успешно отправлен')

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

    def _secure_connection_is_established(self) -> bool:
        request = self._relaible_recieve()
        if request == 'Get RSA public key':
            self._send_rsa_pubkey()
            ciphered_key = bytes.fromhex(self._relaible_recieve()['aes_key'])
            cipher = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher.decrypt(ciphered_key)
            self.aes_cipher = AEScipher(aes_key)
            logging.info('[+] Ключ AES был успешно получен %s', aes_key.hex())
            self._reliable_send('200: OK')
            return True
        self._reliable_send('400: Bad Request')
        return False

    def run(self):
        if self._secure_connection_is_established():
            response_data_raw = self._relaible_recieve()
            response_data = self.aes_cipher.decrypt(
                                            bytes.fromhex(response_data_raw))
            print(response_data)
            if response_data == b'Get image':
                self._reliable_send(self.aes_cipher.encrypt(b'200: OK').hex())
            else:
                self._reliable_send('400: Bad Request')
        else:
            self._reliable_send('400: Bad Request')
            print('Here!')


if __name__ == '__main__':
    reciever = Server('192.168.1.2', 4444)
    try:
        reciever.run()
    except KeyboardInterrupt:
        reciever.close_socket()
    except Exception as err:
        logging.exception(err)
