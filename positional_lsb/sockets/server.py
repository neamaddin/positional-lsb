from ntpath import basename
import logging
import pickle
import socket
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from positional_lsb.sockets.sock import SecureSocket, Status
from positional_lsb.ciphers import AEScipher


logging.basicConfig(
    level=logging.INFO,
    filename="server.log",
    filemode="a",
    format="%(asctime)s %(levelname)s %(message)s",
)
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
        logger.info(
            "[+] Ключи были успешно сгенирированны: %s, %s",
            self.public_key,
            self.private_key,
        )
        logger.info("[+] Ожидание входяших подключений")
        self._connection, address = listener.accept()
        logger.info("[+] Установлено соединение с клиентом %s", address)
        super().__init__(self._connection)

    def _send_rsa_pubkey(self) -> None:
        logger.info("[+] Запрошен публичный ключ (RSA)")
        pubkey = pickle.dumps([self.public_key.n, self.public_key.e])
        self._send(pubkey)
        logger.info("[+] Публичный ключ RSA был успешно отправлен")

    def establish_secure_connection(self) -> None:
        request = self._recv()
        if request == b"Get RSA public key":
            self._send_rsa_pubkey()
            aes_key_msg = self._recv()
            if aes_key_msg is not None:
                ciphered_key = pickle.loads(aes_key_msg)["aes_key"]
                cipher = PKCS1_OAEP.new(self.private_key)
                aes_key = cipher.decrypt(ciphered_key)
                logger.info(
                    "[+] Ключ AES был успешно получен %s",
                    aes_key.hex()
                )
                self._send(Status.OK.value)
                self.set_aes_cipher(AEScipher(aes_key))
        else:
            self._send(Status.BAD_REQUEST.value)

    def send_image(self, image_path: str) -> None:
        if self._connection_is_secure and self._recv() == b"Get image":
            logger.info("[+] Было запрошено изображение")
            with open(image_path, "rb") as image:
                data = {
                    "filename": basename(image_path),
                    "image": image.read()
                }
                self._send(pickle.dumps(data))
            if self._recv() == Status.OK.value:
                logger.info("[+] Изображение было успешно получено")
        else:
            self._send(Status.BAD_REQUEST.value)

    def close_socket(self) -> None:
        self._connection.close()
        logger.info("[-] Сокет был успешно закрыт")
