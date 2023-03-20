import socket
import pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
import pytest

from positional_lsb.sockets.server import Server
from positional_lsb.sockets.sock import SecureSocket, Status
from .conftest import get_test_data


RAW_RSA_PUBLIC_KEY = get_test_data('RSA_public_key.pickle')
RSA_PUBLIC_KEY = pickle.loads(RAW_RSA_PUBLIC_KEY)
RAW_AES_KEY = get_test_data('AES_key.pickle')
CIPHERED_AES_KEY = pickle.loads(RAW_AES_KEY)['aes_key']
AES_KEY = b'J\xb9\x8d\xa3\xa7F\x08p\x0c\x95\xdd\x99\x963JE'


class TestServer:
    def test_init_server(self, server_mock, mocker, caplog):
        socket.socket.accept.assert_called_once()
        caplog.clear()

    def test_pr_send_rsa_pubkey(self, server_mock, mocker, caplog):
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._send')
        server_mock.public_key = RSA.construct(RSA_PUBLIC_KEY)
        server_mock._send_rsa_pubkey()
        SecureSocket._send.assert_called_with(RAW_RSA_PUBLIC_KEY)
        caplog.clear()

    def test_establish_secure_connection_bad_request(
            self, server_mock, mocker, caplog):
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._send')
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     return_value=b'')
        server_mock.establish_secure_connection()
        SecureSocket._send.assert_called_with(Status.BAD_REQUEST.value)
        caplog.clear()

    def test_establish_secure_connection(self, server_mock, mocker, caplog):
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._send')
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     side_effect=[b'Get RSA public key', RAW_AES_KEY])
        mocker.patch('positional_lsb.sockets.sock.SecureSocket.set_aes_cipher')
        mocker.patch('positional_lsb.sockets.server.Server._send_rsa_pubkey')
        mocker.patch('Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.decrypt',
                     return_value=AES_KEY)
        server_mock.establish_secure_connection()
        Server._send_rsa_pubkey.assert_called_once()
        PKCS1OAEP_Cipher.decrypt.assert_called_with(CIPHERED_AES_KEY)
        SecureSocket._send.assert_called_with(Status.OK.value)
        SecureSocket.set_aes_cipher.assert_called_once()
        caplog.clear()

    @pytest.mark.parametrize('path_for_image', ['img.jpg'], indirect=True)
    def test_send_image_bad_request(
            self, server_mock, mocker, path_for_image, caplog):
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._send')
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     return_value=b'')
        server_mock.send_image(path_for_image)
        SecureSocket._send.assert_called_with(Status.BAD_REQUEST.value)
        caplog.clear()

    @pytest.mark.parametrize('path_for_image', ['img.jpg'], indirect=True)
    def test_send_image(self, server_mock, path_for_image, mocker, caplog):
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._send')
        mocker.patch('positional_lsb.sockets.sock.SecureSocket._recv',
                     side_effect=[b'Get image', Status.OK.value])
        server_mock._connection_is_secure = True
        server_mock.send_image(path_for_image)
        SecureSocket._send.assert_called_once()
        caplog.clear()

    def test_close_socket(self, server_mock, mocker, caplog):
        mocker.patch('socket.socket.close')
        server_mock.close_socket()
        socket.socket.close.assert_called_once()
        caplog.clear()
