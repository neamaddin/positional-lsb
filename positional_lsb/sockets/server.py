from ntpath import basename
import logging
import pickle
import socket
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from positional_lsb.sockets.sock import SecureSocket
from positional_lsb.aes import AEScipher


logging.basicConfig(level=logging.INFO, filename='server.log', filemode='a',
                    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))


class Server(SecureSocket):
    def __init__(self, ip_address: str, port: int):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip_address, port))
        listener.listen(0)
        self.private_key = RSA.generate(3072)
        self.public_key = self.private_key.public_key()
        logging.info('[+] Ключи были успешно сгенирированны: %s, %s',
                     self.public_key, self.private_key)
        logging.info('[+] Ожидание входяших подключений')
        self._connection, address = listener.accept()
        logging.info('[+] Установлено соединение с клиентом %s', address)
        super().__init__(self._connection)

    def _send_rsa_pubkey(self) -> None:
        logging.info('[+] Запрошен публичный ключ (RSA)')
        pubkey = pickle.dumps([self.public_key.n, self.public_key.e])
        self._send(pubkey)
        logging.info('[+] Публичный ключ RSA был успешно отправлен')

    def establish_secure_connection(self) -> None:
        request = self._recv()
        if request == b'Get RSA public key':
            self._send_rsa_pubkey()
            aes_key_msg = self._recv()
            if aes_key_msg is not None:
                ciphered_key = pickle.loads(aes_key_msg)['aes_key']
                cipher = PKCS1_OAEP.new(self.private_key)
                aes_key = cipher.decrypt(ciphered_key)
                logging.info('[+] Ключ AES был успешно получен %s', aes_key.hex())
                self._send(b'200: OK')
                self.set_aes_cipher(AEScipher(aes_key))
        else:
            self._send(b'400: Bad Request')

    def send_image(self, image_path: str) -> None:
        if self._connection_is_secure and self._recv() == b'Get image':
            logging.info('[+] Было запрошено изображение')
            with open(image_path, 'rb') as image:
                data = {
                    'filename': basename(image_path),
                    'image': image.read()
                    }
                self._send(pickle.dumps(data))
            if self._recv() == b'Get image':
                logging.info('[+] Изображение было успешно получено')
        else:
            self._send(b'400: Bad Request')

    def close_socket(self) -> None:
        self._connection.close()
        logging.info('[-] Сокет был успешно закрыт')


if __name__ == '__main__':
    try:
        reciever = Server('192.168.1.2', 4444)
        reciever.establish_secure_connection()
        reciever.send_image('../../new.png')
    except KeyboardInterrupt:
        reciever.close_socket()
    except Exception as err:
        logging.exception(err)
