import socket

from positional_lsb.sockets.sock import Status, SecureSocket
from positional_lsb.sockets.client import Client
from .conftest import get_test_data


RSA_PUBLIC_KEY = get_test_data('RSA_public_key.pickle')
IMAGE_FILE = get_test_data('image_file.pickle')


class TestClient:
    client = Client('127.0.0.1', 4444)

    def test_pr_aes_key_ship_status(self, caplog, mocker):
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     return_value=Status.OK.value)
        mocker.patch('positional_lsb.sockets.sock.SecureSocket.set_aes_cipher')
        self.client._aes_key_ship_status()
        SecureSocket.set_aes_cipher.assert_called_once()

        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     return_value=None)
        mocker.patch('socket.socket.close')
        self.client._aes_key_ship_status()
        socket.socket.close.assert_called_once()
        caplog.clear()

    def test_establish_secure_connection(self, mocker, caplog):
        mocker.patch('socket.socket.connect')
        send_mock = mocker.patch('socket.socket.send')
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     return_value=RSA_PUBLIC_KEY)
        mocker.patch(
            'positional_lsb.sockets.client.Client._aes_key_ship_status')
        self.client.establish_secure_connection()
        socket.socket.connect.assert_called_with(('127.0.0.1', 4444))
        assert send_mock.call_count == 2
        Client._aes_key_ship_status.assert_called_once()
        caplog.clear()

    def test_get_image(self, mocker, caplog):
        send_mock = mocker.patch(
            'positional_lsb.sockets.sock.SecureSocket._send')
        mocker.patch(
            'positional_lsb.sockets.sock.SecureSocket._recv',
            return_value=IMAGE_FILE
        )
        mocker.patch('builtins.open')
        self.client._connection_is_secure = True
        self.client.get_image()
        SecureSocket._recv.assert_called_once()
        assert send_mock.call_count == 2
        open.assert_called_with('tmp.png', 'wb')

        self.client._connection_is_secure = False
        assert self.client.get_image() is None
        caplog.clear()

    def test_close_socket(self, mocker, caplog):
        mocker.patch('socket.socket.close')
        self.client.close_socket()
        socket.socket.close.assert_called_once()
        caplog.clear()
