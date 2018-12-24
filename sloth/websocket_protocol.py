#!/usr/bin/env python3

"""
WebSocket protocol parsing, no IO.
"""

import os
import base64
import hashlib
import struct
from collections import OrderedDict
from bitstring import Bits


__all__ = (
    'WebSocketClientHandshake', 'WebSocketFrameHeader', 'websocket_mask',
    'pack_2bytes', 'pack_8bytes', 'unpack_2bytes', 'unpack_8bytes')


def pack_2bytes(i: int) -> bytes:
    """
    Convert int to `bytes` object of length 2 in network byteorder.
    """
    return struct.pack('!H', i)


def pack_8bytes(i: int) -> bytes:
    """
    Convert int to `bytes` object of length 8 in network byteorder.
    """
    return struct.pack('!Q', i)


def unpack_2bytes(b: bytes) -> int:
    """
    Convert `bytes` object of length 2 in network byteorder to int.
    """
    return struct.unpack('!H', b)[0]


def unpack_8bytes(b: bytes) -> int:
    """
    Convert `bytes` object of length 8 in network byteorder to int.
    """
    return struct.unpack('!Q', b)[0]


class WebSocketError(Exception):
    """raise when parse WebSocket error"""


def websocket_mask(mask, data):
    """
    `mask` is a `bytes` object of length 4;
    `data` is a `bytes` object of any length.
    Return a `bytes` object of the same length as `data`.
    Use the same function to mask and unmask.
    """

    if not isinstance(mask, bytes) or not isinstance(data, bytes):
        raise WebSocketError('Frame mask and data must be bytes')

    if len(mask) != 4:
        raise WebSocketError('Frame mask must have 4 bytes')

    output = bytearray(data)
    for i in range(len(data)):
        output[i] = data[i] ^ mask[i%4]

    return bytes(output)


class WebSocketFrameHeader():
    """
    Only include the first 16 bits (or 2 bytes).
    Since this class does not involve IO, following data are not handled.
    """

    OPCODE_CONTINUATION = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xA

    CLOSE_OK = 1000
    CLOSE_GOING_AWAY = 1001
    CLOSE_PROTOCOL_ERROR = 1002
    CLOSE_UNSUPPORTED_DATA = 1003
    CLOSE_INVALID_TEXT = 1007
    CLOSE_POLICY_VIOLATION = 1008
    CLOSE_MESSAGE_TOO_BIG = 1009
    CLOSE_MANDATORY_EXTENSION = 1010
    CLOSE_INTERNAL_ERROR = 1011
    CLOSE_SERVICE_RESTART = 1012
    CLOSE_TRY_AGAIN_LATER = 1013

    LENGTH_BOUNDARY_1 = 126
    LENGTH_BOUNDARY_2 = 1 << 16
    LENGTH_MARK_1 = 126
    LENGTH_MARK_2 = 127

    def __init__(self, fin=True, rsv1=False, rsv2=False, rsv3=False, opcode=0, mask=True, length=0):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self._opcode = Bits(uint=opcode, length=4)  # 4 bits
        self.mask = mask
        self._length = Bits(uint=self._format_length(length), length=7)  # 7 bits

    def _format_length(self, l):
        if l < self.LENGTH_BOUNDARY_1:
            l = l
        elif l < self.LENGTH_BOUNDARY_2:
            l = self.LENGTH_MARK_1
        else:
            l = self.LENGTH_MARK_2
        return l

    @property
    def opcode(self):
        return self._opcode

    @opcode.setter
    def opcode(self, o):
        self._opcode = Bits(uint=o, length=4)

    @opcode.getter
    def opcode(self):
        return self._opcode.uint

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, l):
        self._length = Bits(uint=self._format_length(l), length=7)

    @length.getter
    def length(self):
        return self._length.uint

    def frombytes(self, data):
        """
        `data` is a `bytes` object of length 2 (2 bytes) in network byteorder.
        """

        if not isinstance(data, bytes):
            raise WebSocketError('Frame header must be bytes')

        if len(data) != 2:
            raise WebSocketError('Frame header must have 2 bytes')

        first_byte = Bits(uint=data[0], length=8)
        second_byte = Bits(uint=data[1], length=8)

        self.fin = first_byte[0]
        self.rsv1 = first_byte[1]
        self.rsv2 = first_byte[2]
        self.rsv3 = first_byte[3]
        self._opcode = first_byte[4:8]

        self.mask = second_byte[0]
        self._length = second_byte[1:8]

    def tobytes(self):
        """
        Convert to `bytes` object of length 2 in network byteorder.
        """

        codes = []

        for code in [self.fin, self.rsv1, self.rsv2, self.rsv3]:
            if code:
                codes.append(Bits(bin='0b1'))
            else:
                codes.append(Bits(bin='0b0'))

        codes.append(self._opcode)

        if self.mask:
            codes.append(Bits(bin='0b1'))
        else:
            codes.append(Bits(bin='0b0'))

        codes.append(self._length)

        return sum(codes).tobytes()


class WebSocketClientHandshake():
    """
    Client side handshake.
    """

    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    SWITCHING_PROTOCOLS = 'HTTP/1.1 101 Switching Protocols\r\n'

    def __init__(self, host, port, uri, header=None):
        self.host = host
        self.port = port
        self.uri = '/{}'.format(uri.strip('/'))
        self.header = header
        self._sec_key = base64.b64encode(os.urandom(16)).decode('ascii')
        self._sec_accept = base64.b64encode(
            hashlib.sha1((self._sec_key+self.GUID).encode('ascii')).digest()).decode('ascii')

    def _header_dict_to_str(self, dict_):
        """
        Convert ordered dict to header string.
        """

        str_ = ''
        for key, value in dict_.items():
            str_ += '{key}: {value}\r\n'.format(key=key, value=value)
        return str_

    def _header_str_to_dict(self, str_):
        """
        Convert header string to ordered dict.
        """

        dict_ = OrderedDict([])
        for line in str_.splitlines():
            if line == self.SWITCHING_PROTOCOLS.strip():
                continue
            key = line.split(': ')[0]
            value = line[len(key)+2:]

            dict_[key] = value
            dict_[key.lower()] = value.lower()  # store a copy in lower case

        return dict_

    def send_handshake_request(self) -> bytes:
        """
        GET /chat HTTP/1.1
        Host: server.example.com:8765
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: iDx2VdlbpyWKk0s8LtxvzA==
        Sec-WebSocket-Version: 13
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
        User-Agent: Python/3.6 websockets/7.0
        """

        if str(self.port) in ('80', '443'):
            header_host = self.host
        else:
            header_host = '{}:{}'.format(self.host, self.port)

        header_dict = OrderedDict([
            ('Host', header_host),
            ('Upgrade', 'websocket'),
            ('Connection', 'Upgrade'),
            ('Sec-WebSocket-Key', self._sec_key),
            ('Sec-WebSocket-Version', '13'),
            ('User-Agent', 'Python/3.6 websockets/7.0'),
            ])

        if self.header:
            header_dict.update(self.header)

        header_str = self._header_dict_to_str(header_dict)

        request_str = 'GET {} HTTP/1.1\r\n'.format(self.uri)
        request_str += header_str
        request_str += '\r\n'
        return request_str.encode('ascii')

    def receive_handshake_response(self, response_str: bytes):
        """
        HTTP/1.1 101 Switching Protocols
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Accept: hwW0n/o6ZD+3DjJX6W726nW0y58=
        Sec-WebSocket-Extensions: permessage-deflate
        Date: Sat, 22 Dec 2018 03:12:45 GMT
        Server: Python/3.6 websockets/7.0
        """

        response_str = response_str.decode('ascii')

        if not response_str.startswith(self.SWITCHING_PROTOCOLS):
            raise WebSocketError('Response not starts with HTTP/1.1 101 Switching Protocols')

        header_str = response_str.split('\r\n\r\n')[0]
        header_dict = self._header_str_to_dict(header_str)

        # use lower case for compatibility
        if header_dict.get('upgrade') != 'websocket':
            raise WebSocketError('Response not include Upgrade: websocket')

        if header_dict.get('connection') != 'upgrade':
            raise WebSocketError('Response not include Connection: Upgrade')

        if header_dict.get('sec-websocket-accept') != self._sec_accept.lower():
            print('Response Sec-WebSocket-Accept: {}'.format(header_dict.get('sec-websocket-accept')))
            print('Should be: {}'.format(self._sec_accept))
            raise WebSocketError('Response Sec-WebSocket-Accept is incorrect')

        return True
