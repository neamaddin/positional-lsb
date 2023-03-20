from hashlib import sha3_256
from typing import Generator
from enum import Enum
import struct

from numpy import ndarray
import cv2

from positional_lsb.exceptions import TooBigFileError
from positional_lsb.pattern import CoordinatesList, ImagePattern
from positional_lsb.ciphers import AEScipher, DES3cipher


BITS_IN_BYTE = 8
BITS_IN_PIXEL = 3
DATA_LEN_PREFIX = 4


class SubpixelLayout(Enum):
    BGR = [0, 1, 2]
    BRG = [0, 2, 1]
    GRB = [1, 2, 0]
    GBR = [1, 0, 2]
    RBG = [2, 0, 1]
    RGB = [2, 1, 0]


class PositionalLSB:
    def __init__(self, pattern: CoordinatesList, sha3_hash: bytes):
        self.sha3_hash = sha3_hash
        self.pattern: CoordinatesList = pattern
        self._output_data: bytearray = bytearray(b"")

    @staticmethod
    def _data_generator(data: bytes) -> Generator[str, None, None]:
        for byte in data:
            for bit_str in "{0:08b}".format(byte):
                yield bit_str

    def _subpixel_layout(self) -> SubpixelLayout:
        match int.from_bytes(self.sha3_hash, "big") % 6:
            case 0:
                return SubpixelLayout.BGR
            case 1:
                return SubpixelLayout.BRG
            case 2:
                return SubpixelLayout.GRB
            case 3:
                return SubpixelLayout.GBR
            case 4:
                return SubpixelLayout.RBG
            case _:
                return SubpixelLayout.RGB

    def _encode_image(
        self, image: ndarray, data_generator: Generator[str, None, None]
    ) -> None:
        for coords in self.pattern:
            for key in self._subpixel_layout().value:
                try:
                    if next(data_generator) == "1":
                        image[coords.y][coords.x][key] |= 0b00000001
                    else:
                        image[coords.y][coords.x][key] &= 0b11111110
                except StopIteration:
                    return

    def _extract_byte(self, image: ndarray) -> Generator[int, None, None]:
        byte = ""
        for coords in self.pattern:
            for key in self._subpixel_layout().value:
                if len(byte) < BITS_IN_BYTE:
                    byte += str(bin(image[coords.y][coords.x][key])[-1])
                else:
                    yield int(byte, 2)
                    byte = str(bin(image[coords.y][coords.x][key])[-1])

    def _decode_image(self, image: ndarray) -> bool:
        byte_from_image = self._extract_byte(image)
        raw_data_len = bytearray(b"")
        for _ in range(DATA_LEN_PREFIX):
            raw_data_len.append(next(byte_from_image))
        data_len = struct.unpack(">I", raw_data_len)[0]
        try:
            for _ in range(data_len):
                self._output_data.append(next(byte_from_image))
            return True
        except StopIteration:
            return False


class PositionalLSBImage(PositionalLSB):
    def __init__(self, container_path: str, password: str = ""):
        self.image: ndarray = cv2.imread(container_path)
        self.password: bytes = password.encode("utf-8")
        self.sha3_hash: bytes = sha3_256(self.password).digest()
        self.pattern_data = ImagePattern(container_path, self.sha3_hash)
        self.pattern: CoordinatesList = self.pattern_data.get_pattern()
        super().__init__(self.pattern, self.sha3_hash)

    def _payload_max_size(self) -> int:
        payload_max_size_without_prefix = (
            self.pattern_data.image_height
            * self.pattern_data.image_width
            * BITS_IN_PIXEL
        ) / BITS_IN_BYTE
        return int(payload_max_size_without_prefix) - DATA_LEN_PREFIX

    def _can_encode(self, data: bytes) -> bool:
        if len(data) < self._payload_max_size():
            return True
        return False

    def encode(self, data: bytes, container_file_path: str) -> None:
        if self._can_encode(data):
            payload = struct.pack(">I", len(data)) + data
            self._encode_image(self.image, self._data_generator(payload))
            cv2.imwrite(container_file_path, self.image)
        else:
            raise TooBigFileError(self._payload_max_size())

    def encode_with_aes(self, data: bytes, container_file_path: str) -> None:
        aes_cipher = AEScipher(self.sha3_hash[:16], self.sha3_hash[16:])
        self.encode(aes_cipher.encrypt(data), container_file_path)

    def encode_with_3des(self, data: bytes, container_file_path: str) -> None:
        cipher = DES3cipher(self.sha3_hash)
        self.encode(cipher._encrypt(data), container_file_path)

    def decode(self) -> bytes:
        self._decode_image(self.image)
        return self._output_data

    def decode_with_aes(self) -> bytes:
        aes_cipher = AEScipher(self.sha3_hash[:16], self.sha3_hash[16:])
        self._decode_image(self.image)
        return aes_cipher.decrypt(self._output_data)

    def decode_with_3des(self) -> bytes:
        cipher = DES3cipher(self.sha3_hash)
        self._decode_image(self.image)
        return cipher._decrypt(self._output_data)
