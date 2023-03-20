import logging
import pickle
import socket
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from positional_lsb.sockets.sock import SecureSocket, Status
from positional_lsb.ciphers import AEScipher


logging.basicConfig(
    level=logging.INFO,
    filename="client.log",
    filemode="a",
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))


class Client(SecureSocket):
    def __init__(self, ip_address: str, port: int):
        self._connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip_address = ip_address
        self.port = port
        self.aes_key = get_random_bytes(16)
        super().__init__(self._connection)

    def _aes_key_ship_status(self) -> None:
        status = self._recv()
        if status == Status.OK.value:
            logger.info("[+] Ключ AES был успешно доставлен")
            self.set_aes_cipher(AEScipher(self.aes_key))
        else:
            logger.info("[-] Что-то пошло не так")
            self._connection.close()

    def establish_secure_connection(self) -> None:
        self._connection.connect((self.ip_address, self.port))
        self._send(b"Get RSA public key")
        raw_rsa_key = self._recv()
        if raw_rsa_key is not None:
            n_value, e_value = pickle.loads(raw_rsa_key)
            public_key = RSA.construct((n_value, e_value))
            logger.info(
                "[+] Публичный ключ был успешно получен: %s",
                public_key
            )
            cipher = PKCS1_OAEP.new(public_key)
            ciphered_key = cipher.encrypt(self.aes_key)
            self._send(pickle.dumps({"aes_key": ciphered_key}))
            self._aes_key_ship_status()

    def get_image(self) -> None:
        if self._connection_is_secure:
            self._send(b"Get image")
            response_data = self._recv()
            if response_data is not None:
                data = pickle.loads(response_data)
                with open(data["filename"], "wb") as image:
                    image.write(data["image"])
                self._send(Status.OK.value)
                logger.info("[+] Изображение было успешно получено")
        else:
            logger.info("[-] Не удалось уcтановить защищенное соединение")

    def close_socket(self) -> None:
        self._connection.close()
        logger.info("[-] Сокет был успешно закрыт")
