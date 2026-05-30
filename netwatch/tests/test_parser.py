from netwatch.parser import parse_socket, parse_connection, parse_data
from netwatch.models import SocketInfo, ConnectionInfo, DataTransfer

import pytest

def test_parse_socket():
    """
    Test parse_socket correctly parses a socket syscall line
    """

    line = 'socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3'
    result = parse_socket(line)

    assert isinstance(result, SocketInfo)
    assert result.family == "PF_INET"
    assert result.sock_type == "SOCK_STREAM"
    assert result.protocol == "IPPROTO_TCP"
    assert result.fd == 3


def test_parse_socket_invalid():
    """
    Test ValueError on parse_socket
    """
    with pytest.raises(ValueError):
        parse_socket("garbage socket test")





def test_parse_connection():
    """
    Test parse_connection correctly parses a connection syscall line
    """

    line = 'connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0'
    result = parse_connection(line)

    assert isinstance(result, ConnectionInfo)
    assert result.fd == 3
    assert result.family == "AF_INET"
    assert result.port == 5555
    assert result.ip == "192.168.10.1"


def test_parse_connection_invalid():
    """
    Test ValueError on parse_connection
    """
    with pytest.raises(ValueError):
        parse_connection("garbage connection test")




def test_parse_data_write():
    """
    Test parse_data correctly parses data transfer syscall line
    """
    line = 'write(3, "Hello World!\n", 13) = 13'
    result = parse_data(line)

    assert isinstance(result, DataTransfer)
    assert result.operation == "write"
    assert result.fd == 3
    assert result.data == "Hello World!\n"
    assert result.bytes_requested == 13
    assert result.bytes_transferred == 13


def test_parse_data_read():
    """
    Test parse_data correctly parses data transfer syscall line
    """
    line = 'read(3, "Boo!\n", 2048) = 5'
    result = parse_data(line)

    assert isinstance(result, DataTransfer)
    assert result.operation == "read"
    assert result.fd == 3
    assert result.data == "Boo!\n"
    assert result.bytes_requested == 2048
    assert result.bytes_transferred == 5


def test_parse_data_invalid():
    """
    Test ValueError on parse_data
    """
    with pytest.raises(ValueError):
        parse_data("garbage connection test")