import socket
import json
import os

import pytest

from positional_lsb.sockets.server import Server
from positional_lsb.stego import PositionalLSBImage


def get_test_data(filename: str):
    folder_path = os.path.abspath(os.path.dirname(__file__))
    folder = os.path.join(folder_path, 'test_data')
    if '.json' in filename:
        json_file = os.path.join(folder, filename)
        with open(json_file, 'r') as file:
            return json.load(file)
    else:
        pickle_file = os.path.join(folder, filename)
        with open(pickle_file, 'rb') as file:
            return file.read()


@pytest.fixture
def path_for_image(request):
    folder_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(folder_path, 'test_data', request.param)


@pytest.fixture
def server_mock(mocker, caplog):
    mock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mocker.patch('socket.socket.accept',
                 return_value=(mock_sock, '127.0.0.1'))
    mocker.Mock('positional_lsb.sockets.sock.SecureSocket')
    caplog.clear()
    return Server('127.0.0.1', 4444)


@pytest.fixture(scope='class')
def pos_lsb_img():
    folder_path = os.path.abspath(os.path.dirname(__file__))
    image_path = os.path.join(folder_path, 'test_data', 'img.jpg')
    return PositionalLSBImage(image_path)
