from subprocess import Popen
from hashlib import sha3_256
from typing import Generator
from enum import Enum
import os

from aes_cipher import DataEncrypter, DataDecrypter
from numpy import ndarray
import cv2

from pattern import CoordinatesList, ImagePattern, VideoPattern


BITS_IN_BYTE = 8
HASH_LENGTH = 32
BITS_IN_PIXEL = 3


class SubpixelLayuot(Enum):
    BGR = [0, 1, 2]
    GRB = [1, 2, 0]
    RGB = [2, 1, 0]


class PositionalLSB():
    def __init__(self, pattern: CoordinatesList, sha3_hash: sha3_256) -> None:
        self.sha3_hash: sha3_256 = sha3_hash
        self.pattern: CoordinatesList = pattern
        self._output_data: bytearray = bytearray(b'')

    def _subpixel_layuot(self) -> SubpixelLayuot:
        layout_index = int.from_bytes(self.sha3_hash.digest(), 'big') % 3
        if layout_index == 0:
            return SubpixelLayuot.BGR
        if layout_index == 1:
            return SubpixelLayuot.GRB
        return SubpixelLayuot.RGB

    def _data_generator(self, data: bytes) -> Generator[str, None, None]:
        for byte in data:
            for bit_str in "{0:08b}".format(byte):
                yield bit_str

    def _encode_image(self, image: ndarray,
                      data_generator: Generator[str, None, None]) -> None:
        for coordinates in self.pattern:
            for key in self._subpixel_layuot().value:
                try:
                    if next(data_generator) == '1':
                        image[coordinates.y][coordinates.x][key] |= 0b00000001
                    else:
                        image[coordinates.y][coordinates.x][key] &= 0b11111110
                except StopIteration:
                    return

    def _decode_image(self, image: ndarray) -> bool:
        byte = ''
        for coordinates in self.pattern:
            for key in self._subpixel_layuot().value:
                if len(byte) < BITS_IN_BYTE:
                    byte += str(bin(image[coordinates.y][coordinates.x][key])[-1])
                else:
                    byte_int = int(byte, 2)
                    self._output_data.append(byte_int)
                    if self._output_data[-HASH_LENGTH:] == self.sha3_hash.digest():
                        return True
                    byte = str(bin(image[coordinates.y][coordinates.x][key])[-1])
        return False


class PositionalLSBImage(PositionalLSB):
    def __init__(self, container_path: str, password: str) -> None:
        self.image: ndarray = cv2.imread(container_path)
        self.password: bytes = password.encode('utf-8')
        self.sha3_hash: sha3_256 = sha3_256(self.password)
        self.pattern_data = ImagePattern(container_path, self.sha3_hash)
        self.pattern: CoordinatesList = self.pattern_data.get_pattern()
        super().__init__(self.pattern, self.sha3_hash)

    def _can_encode(self, payload_path: str) -> bool:
        payload_max_size = (self.pattern_data.image_height * \
            self.pattern_data.image_width * BITS_IN_PIXEL ) / BITS_IN_BYTE
        if (os.path.getsize(payload_path) + HASH_LENGTH) < payload_max_size:
            return True
        return False

    def encode(self, payload_path: str, container_file_path: str) -> None:
        if self._can_encode(payload_path):
            with open(payload_path, 'rb') as file:
                data = file.read() + self.sha3_hash.digest()
            self._encode_image(self.image, self._data_generator(data))
            cv2.imwrite(container_file_path, self.image)
        else:
            print('Can`t encode')

    def encode_with_aes(self, payload_path: str,
                        container_file_path: str) -> None:
        if self._can_encode(payload_path):
            with open(payload_path, 'rb') as file:
                aes_encrypt = DataEncrypter()
                aes_encrypt.Encrypt(file.read(), [self.password])
                data = aes_encrypt.GetEncryptedData() + self.sha3_hash.digest()
            self._encode_image(self.image, self._data_generator(data))
            cv2.imwrite(container_file_path, self.image)
        else:
            print('Can`t encode')

    def decode(self, output_file_path: str) -> None:
        with open(output_file_path, 'wb') as file:
            self._decode_image(self.image)
            file.write(self._output_data[:-HASH_LENGTH])

    def decode_with_aes(self, output_file_path: str) -> None:
        with open(output_file_path, 'wb') as file:
            self._decode_image(self.image)
            aes_decrypt = DataDecrypter()
            aes_decrypt.Decrypt(
                self._output_data[:-HASH_LENGTH],
                [self.password]
            )
            file.write(aes_decrypt.GetDecryptedData())


class PositionalLSBVideo(PositionalLSB):
    def __init__(self, container_path: str, password: str) -> None:
        self.container_path = container_path
        self.video = cv2.VideoCapture(container_path)
        self.current_frame: ndarray
        self.password: bytes = password.encode('utf-8')
        self.sha3_hash = sha3_256(self.password)
        self.pattern_data = VideoPattern(container_path, self.sha3_hash)
        self.pattern: CoordinatesList = self.pattern_data.get_pattern()
        super().__init__(self.pattern, self.sha3_hash)

    def _can_encode(self, payload_path: str) -> bool:
        height = self.video.get(cv2.CAP_PROP_FRAME_HEIGHT)
        width = self.video.get(cv2.CAP_PROP_FRAME_WIDTH)
        fps = self.video.get(cv2.CAP_PROP_FPS)
        frame_count = self.video.get(cv2.CAP_PROP_FRAME_COUNT)
        payload_max_size = (height * width * BITS_IN_PIXEL / BITS_IN_BYTE) * fps
        if (os.path.getsize(payload_path) + HASH_LENGTH) < payload_max_size:
            return True
        return False

    def _separate_audio(self) -> None:
        Popen(['ffmpeg',
            '-i', self.container_path,
            '-q:a', '0', '-map', 'a', 'audio.mp3']).wait()

    def _render_video(self, container_file_path: str) -> None:
        Popen(['ffmpeg',
            '-r' , str(int(self.video.get(cv2.CAP_PROP_FPS))),
            '-i', 'frames\\%08d.png',
            '-i', 'audio.mp3',
            '-vcodec', 'rawvideo',
            '-pix_fmt', 'rgb32',
            '-acodec', 'copy',
            container_file_path + '.avi']).wait()

    def encode(self, payload_path: str, container_file_path: str) -> None:
        if self._can_encode(payload_path):
            with open(payload_path, 'rb') as file:
                data = file.read() + self.sha3_hash.digest()
            data_generator = self._data_generator(data)
            if os.path.exists('frames'):
                os.remove('frames')
                os.mkdir('frames')
            else:
                os.mkdir('frames')
            frame_index = 1
            while self.video.isOpened():
                ret, frame = self.video.read()
                if ret:
                    self.current_frame = frame
                    self._encode_image(self.current_frame, data_generator)
                    cv2.imwrite('frames/{:08d}.png'.format(frame_index),
                                self.current_frame)
                    frame_index += 1
                else:
                    break
            self._separate_audio()
            self._render_video(container_file_path)
            self.video.release()
        else:
            print('Can`t encode')

    def decode(self, output_file_path: str) -> None:
        with open(output_file_path, 'wb') as file:
            while self.video.isOpened():
                ret, frame = self.video.read()
                if ret:
                    if self._decode_image(frame):
                        break
            file.write(self._output_data[:-HASH_LENGTH])
        self.video.release()


# if __name__ == '__main__':
#     lsb_encode = PositionalLSBImage('img.jpg', 'Passw0rd')
#     lsb_encode.encode_with_aes('requirements.txt', 'new.png')

#     lsb_decode = PositionalLSBImage('new.png', 'Passw0rd')
#     lsb_decode.decode_with_aes('1.txt')

# if __name__ == '__main__':
#     lsb_encode = PositionalLSBVideo('video.mp4', 'Passw0rd')
#     lsb_encode.encode('requirements.txt', 'video')

#     lsb_decode = PositionalLSBVideo('video.avi', 'Passw0rd')
#     lsb_decode.decode('2.txt')
