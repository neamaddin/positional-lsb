from socket import socket
from enum import Enum
import struct

from positional_lsb.exceptions import NonSocketObjectError
from positional_lsb.ciphers import AEScipher


class Status(Enum):
    OK = b"200: OK"
    BAD_REQUEST = b"400: Bad Request"


class SecureSocket:
    def __init__(self, sock: socket):
        if not isinstance(sock, socket):
            raise NonSocketObjectError
        self._aes_cipher: AEScipher
        self._connection_is_secure = False
        self._socket = sock

    def set_aes_cipher(self, aes_cipher: AEScipher) -> None:
        self._aes_cipher = aes_cipher
        self._connection_is_secure = True

    def _recvall(self, data_len: int) -> bytes | None:
        if isinstance(data_len, bool):
            raise TypeError
        data = b""
        while len(data) < data_len:
            packet = self._socket.recv(data_len - len(data))
            if not packet:
                return None
            data += packet
        return data

    def _recv(self) -> bytes | None:
        raw_data_len = self._recvall(4)
        if not raw_data_len:
            return None
        data_len = struct.unpack(">I", raw_data_len)[0]
        data = self._recvall(data_len)
        if self._connection_is_secure and data is not None:
            data = self._aes_cipher.decrypt(data)
        return data

    def _send(self, data: bytes) -> None:
        if self._connection_is_secure:
            data = self._aes_cipher.encrypt(data)
        data = struct.pack(">I", len(data)) + data
        self._socket.send(data)
