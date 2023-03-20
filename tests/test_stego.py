from hashlib import sha3_256
import pickle
import struct

import numpy as np
import pytest
import cv2

from positional_lsb.exceptions import TooBigFileError
from positional_lsb.ciphers import AEScipher, DES3cipher
from positional_lsb.pattern import Pattern
from positional_lsb.stego import PositionalLSB, SubpixelLayout
from .conftest import get_test_data


GENERATOR_DATA = get_test_data('generator_data.json')
FILLED_IMAGE = pickle.loads(get_test_data('filled_image.pickle'))

SHA3_256_DEFAULT = sha3_256(b'').digest()
FULL_HD_MAX_SIZE = 777596
FULL_HD_MAX_SIZE_ALLOWED = FULL_HD_MAX_SIZE - 1


class TestPositionalLSB:
    pattern = Pattern(10, 10, SHA3_256_DEFAULT).get_pattern()
    positional_lsb = PositionalLSB(pattern, SHA3_256_DEFAULT)
    data = b'Positional LSB is cool!'
    payload = struct.pack(">I", len(data)) + data

    def test_pr_data_generator(self):
        generator = PositionalLSB._data_generator(self.data)
        assert GENERATOR_DATA == list(generator)

    @pytest.mark.parametrize(
        ('hash_bytes', 'subpixel_layout'), [
            (b'\x00', SubpixelLayout.BGR),
            (b'\x01', SubpixelLayout.BRG),
            (b'\x02', SubpixelLayout.GRB),
            (b'\x03', SubpixelLayout.GBR),
            (b'\x04', SubpixelLayout.RBG),
            (b'\x05', SubpixelLayout.RGB),
        ]
    )
    def test_pr_subpixel_layout(self, hash_bytes, subpixel_layout):
        layout = PositionalLSB(self.pattern, hash_bytes)._subpixel_layout()
        assert layout == subpixel_layout

    @pytest.mark.parametrize('path_for_image', ['img.jpg'], indirect=True)
    def test_pr_encode_image(self, path_for_image):
        generator = PositionalLSB._data_generator(self.payload)
        image = cv2.imread(path_for_image)
        self.positional_lsb._encode_image(image, generator)
        assert np.array_equal(image, FILLED_IMAGE) is True

    def test_pr_extract_byte(self):
        extract_generator = self.positional_lsb._extract_byte(FILLED_IMAGE)
        for bit in self.payload:
            assert next(extract_generator) == bit

    def test_pr_decode_image(self):
        assert self.positional_lsb._decode_image(FILLED_IMAGE) is True
        assert self.positional_lsb._output_data == self.data

    @pytest.mark.parametrize('path_for_image', ['img.jpg'], indirect=True)
    def test_pr_decode_image_not_correct(self, path_for_image):
        image = cv2.imread(path_for_image)
        assert self.positional_lsb._decode_image(image) is False


@pytest.mark.usefixtures('pos_lsb_img')
class TestPositionalLSBImage:
    def test_pr_payload_max_size(self, pos_lsb_img):
        assert pos_lsb_img._payload_max_size() == FULL_HD_MAX_SIZE

    @pytest.mark.parametrize(
        ('data_bytes', 'return_value_bool'), [
            (bytearray(FULL_HD_MAX_SIZE_ALLOWED), True),
            (bytearray(FULL_HD_MAX_SIZE), False),
        ]
    )
    def test_pr_can_encode(self, data_bytes, return_value_bool, pos_lsb_img):
        can_encode = pos_lsb_img._can_encode(data_bytes)
        assert can_encode is return_value_bool

    def test_encode(self, mocker, pos_lsb_img):
        mocker.patch('cv2.imwrite')
        mocker.patch('positional_lsb.stego.PositionalLSB._encode_image')
        pos_lsb_img.encode(bytearray(FULL_HD_MAX_SIZE_ALLOWED), 'new.png')
        PositionalLSB._encode_image.assert_called_once()
        cv2.imwrite.assert_called_with('new.png', pos_lsb_img.image)

    def test_encode_error(self, pos_lsb_img):
        with pytest.raises(TooBigFileError):
            pos_lsb_img.encode(bytearray(FULL_HD_MAX_SIZE), 'new.png')

    def test_encode_with_aes(self, mocker, pos_lsb_img):
        mocker.patch('positional_lsb.ciphers.AEScipher.encrypt')
        mocker.patch('positional_lsb.stego.PositionalLSBImage.encode')
        data = bytearray(FULL_HD_MAX_SIZE_ALLOWED)
        pos_lsb_img.encode_with_aes(data, 'new.png')
        AEScipher.encrypt.assert_called_with(data)
        pos_lsb_img.encode.assert_called_once()

    def test_encode_with_3des(self, mocker, pos_lsb_img):
        mocker.patch('positional_lsb.ciphers.DES3cipher._encrypt')
        mocker.patch('positional_lsb.stego.PositionalLSBImage.encode')
        data = bytearray(FULL_HD_MAX_SIZE_ALLOWED)
        pos_lsb_img.encode_with_3des(data, 'new.png')
        DES3cipher._encrypt.assert_called_with(data)
        pos_lsb_img.encode.assert_called_once()

    def test_decode(self, mocker, pos_lsb_img):
        mocker.patch('positional_lsb.stego.PositionalLSB._decode_image')
        pos_lsb_img.decode()
        PositionalLSB._decode_image.assert_called_with(pos_lsb_img.image)

    def test_decode_with_aes(self, mocker, pos_lsb_img):
        mocker.patch('positional_lsb.stego.PositionalLSB._decode_image')
        mocker.patch('positional_lsb.ciphers.AEScipher.decrypt')
        pos_lsb_img.decode_with_aes()
        PositionalLSB._decode_image.assert_called_with(pos_lsb_img.image)
        AEScipher.decrypt.assert_called_once()

    def test_decode_with_3des(self, mocker, pos_lsb_img):
        mocker.patch('positional_lsb.stego.PositionalLSB._decode_image')
        mocker.patch('positional_lsb.ciphers.DES3cipher._decrypt')
        pos_lsb_img.decode_with_3des()
        PositionalLSB._decode_image.assert_called_with(pos_lsb_img.image)
        DES3cipher._decrypt.assert_called_once()
