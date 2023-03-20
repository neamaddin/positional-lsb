from subprocess import Popen
from hashlib import sha3_256
import os

from numpy import ndarray
import cv2

from positional_lsb.pattern import CoordinatesList, Pattern
from positional_lsb.stego import BITS_IN_BYTE, BITS_IN_PIXEL, PositionalLSB


HASH_LENGTH = 32


class VideoPattern(Pattern):
    def __init__(self, video_path: str, sha3_hash: bytes):
        video = cv2.VideoCapture(video_path)
        video_width = int(video.get(cv2.CAP_PROP_FRAME_WIDTH))
        video_height = int(video.get(cv2.CAP_PROP_FRAME_HEIGHT))
        video.release()
        super().__init__(video_width, video_height, sha3_hash)


class PositionalLSBVideo(PositionalLSB):
    def __init__(self, container_path: str, password: str):
        self.container_path = container_path
        self.video = cv2.VideoCapture(container_path)
        self.current_frame: ndarray
        self.password: bytes = password.encode("utf-8")
        self.sha3_hash = sha3_256(self.password).digest()
        self.pattern_data = VideoPattern(container_path, self.sha3_hash)
        self.pattern: CoordinatesList = self.pattern_data.get_pattern()
        super().__init__(self.pattern, self.sha3_hash)

    def _can_encode(self, payload_path: str) -> bool:
        height = self.video.get(cv2.CAP_PROP_FRAME_HEIGHT)
        width = self.video.get(cv2.CAP_PROP_FRAME_WIDTH)
        frame_count = self.video.get(cv2.CAP_PROP_FRAME_COUNT)
        bytes_in_frame = height * width * BITS_IN_PIXEL / BITS_IN_BYTE
        payload_max_size = bytes_in_frame * frame_count
        if (os.path.getsize(payload_path) + HASH_LENGTH) < payload_max_size:
            return True
        return False

    def _separate_audio(self) -> None:
        Popen(
            [
                "ffmpeg", "-i", self.container_path,
                "-q:a", "0", "-map", "a", "audio.mp3"
            ]
        ).wait()

    def _render_video(self, container_file_path: str) -> None:
        Popen(
            [
                "ffmpeg",
                "-r",
                str(int(self.video.get(cv2.CAP_PROP_FPS))),
                "-i",
                "frames\\%08d.png",
                "-i",
                "audio.mp3",
                "-vcodec",
                "rawvideo",
                "-pix_fmt",
                "rgb32",
                "-acodec",
                "copy",
                container_file_path + ".avi",
            ]
        ).wait()

    def encode(self, payload_path: str, container_file_path: str) -> None:
        if self._can_encode(payload_path):
            with open(payload_path, "rb") as file:
                data = file.read() + self.sha3_hash
            data_generator = self._data_generator(data)
            if os.path.exists("frames"):
                os.remove("frames")
                os.mkdir("frames")
            else:
                os.mkdir("frames")
            frame_index = 1
            while self.video.isOpened():
                ret, frame = self.video.read()
                if ret:
                    self.current_frame = frame
                    self._encode_image(self.current_frame, data_generator)
                    cv2.imwrite(
                        "frames/{:08d}.png".format(frame_index),
                        self.current_frame
                    )
                    frame_index += 1
                else:
                    break
            self._separate_audio()
            self._render_video(container_file_path)
            self.video.release()
        else:
            print("Can`t encode")

    def decode(self, output_file_path: str) -> None:
        with open(output_file_path, "wb") as file:
            while self.video.isOpened():
                ret, frame = self.video.read()
                if ret:
                    if self._decode_image(frame):
                        break
            file.write(self._output_data[:-HASH_LENGTH])
        self.video.release()
