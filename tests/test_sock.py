from hashlib import sha3_256
import socket
import struct

import pytest

from positional_lsb.exceptions import NonSocketObjectError
from positional_lsb.sockets.sock import SecureSocket
from positional_lsb.ciphers import AEScipher


RAW_DATA = b'Hello'
ENCRYPTED_DATA = b'\xa64kSn'
DUMP_OF_DATA = struct.pack('>I', len(RAW_DATA)) + RAW_DATA
DUMP_OF_ENCRYPTED_DATA = struct.pack('>I', len(ENCRYPTED_DATA)) + ENCRYPTED_DATA


def test_securesocket_init():
    with pytest.raises(NonSocketObjectError):
        SecureSocket('')
    sock = SecureSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    assert isinstance(sock, SecureSocket)


class TestSecureSocket:
    mock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = SecureSocket(mock_sock)

    def test_set_aes_cipher(self):
        assert self.sock._connection_is_secure is False
        self.sock.set_aes_cipher(AEScipher(sha3_256(b'').digest()))
        assert isinstance(self.sock._aes_cipher, AEScipher)
        assert self.sock._connection_is_secure is True

    @pytest.mark.parametrize('data_len', ['', b'', True, 1.5])
    def test_pr_recvall_error(self, data_len):
        with pytest.raises(TypeError):
            self.sock._recvall(data_len)

    def test_pr_recvall(self, monkeypatch):
        buffer_is_empty = False

        def mock_socket_recv(*args, **kwargs):
            nonlocal buffer_is_empty
            if buffer_is_empty:
                return None
            return b'\0'

        monkeypatch.setattr('socket.socket.recv', mock_socket_recv)
        assert self.sock._recvall(0) == b''
        assert self.sock._recvall(10) == b'\0' * 10
        buffer_is_empty = True
        assert self.sock._recvall(0) == b''
        assert self.sock._recvall(10) is None

    def test_pr_recv(self, monkeypatch):
        buffer_is_empty = True

        def mock_socket_recvall(secure_socket_obj, data_len):
            nonlocal buffer_is_empty
            if buffer_is_empty:
                return None
            if data_len == 4:
                return struct.pack('>I', len(RAW_DATA))
            if self.sock._connection_is_secure:
                return ENCRYPTED_DATA
            return RAW_DATA

        monkeypatch.setattr(
            'positional_lsb.sockets.sock.SecureSocket._recvall',
            mock_socket_recvall
        )
        assert self.sock._recv() is None
        buffer_is_empty = False
        self.sock._connection_is_secure = False
        assert self.sock._recv() == RAW_DATA
        self.sock._connection_is_secure = True
        assert self.sock._recv() == RAW_DATA

    @pytest.mark.parametrize('data', ['', 1, True, 1.5])
    def test_pr_send_error(self, data):
        self.sock._connection_is_secure = False
        with pytest.raises(TypeError):
            self.sock._send(data)

    def test_pr_send(self, mocker):
        mocker.patch('socket.socket.send')
        self.sock._connection_is_secure = False
        self.sock._send(RAW_DATA)
        socket.socket.send.assert_called_with(DUMP_OF_DATA)
        self.sock._connection_is_secure = True
        self.sock._send(RAW_DATA)
        socket.socket.send.assert_called_with(DUMP_OF_ENCRYPTED_DATA)
