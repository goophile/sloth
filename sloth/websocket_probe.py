#!/usr/bin/env python3

import os
import socket
import ssl

from .websocket_protocol import (
    WebSocketClientHandshake, WebSocketFrameHeader, websocket_mask,
    pack_2bytes, pack_8bytes, unpack_2bytes, unpack_8bytes)


class IncompleteReadError(Exception):
    """
    Raise on empty socket data read.
    """

def _recv_exactly(session, n):
    """
    receive exactly n bytes from stream socket
    """
    total = b''
    left = n

    while True:

        current = session.recv(left)

        if not current:
            raise IncompleteReadError('Should read {} bytes, but got {} bytes'.format(n, n-left))
        else:
            total += current

        if len(total) == n:
            break
        else:
            left -= len(current)

    return total


def _send_message(session, data, opcode):
    msg_len = len(data)

    frame = WebSocketFrameHeader(opcode=opcode, length=msg_len)

    header = frame.tobytes()

    if msg_len < WebSocketFrameHeader.LENGTH_BOUNDARY_1:
        header += b''
    elif msg_len < WebSocketFrameHeader.LENGTH_BOUNDARY_2:
        header += pack_2bytes(msg_len)
    else:
        header += pack_8bytes(msg_len)

    masking_key = os.urandom(4)

    data = websocket_mask(masking_key, data)

    session.sendall(header+masking_key+data)


def _receive_message(session):
    header = _recv_exactly(session, 2)
    frame = WebSocketFrameHeader()
    frame.frombytes(header)

    if frame.mask:
        raise Exception('should not mask on server side')

    if frame.length == WebSocketFrameHeader.LENGTH_MARK_1:
        msg_len = unpack_2bytes(_recv_exactly(session, 2))
    elif frame.length == WebSocketFrameHeader.LENGTH_MARK_2:
        msg_len = unpack_8bytes(_recv_exactly(session, 8))
    else:
        msg_len = frame.length

    data = _recv_exactly(session, msg_len)
    print('received opcode', frame.opcode)
    print('received length', msg_len)
    if msg_len < 100:
        print('received data', data)

    if frame.opcode == WebSocketFrameHeader.OPCODE_CLOSE and msg_len == 2:
        print('received close reason', unpack_2bytes(data))


def _close_websocket(session):
    data = pack_2bytes(WebSocketFrameHeader.CLOSE_OK)
    _send_message(session, data, WebSocketFrameHeader.OPCODE_CLOSE)


def _handshake(session, host, port, path):
    ws = WebSocketClientHandshake(host, port, path)

    request_str = ws.send_handshake_request()
    session.sendall(request_str)

    data = session.recv(10240)
    ws.receive_handshake_response(data)


def _probe(session, length, message_type):
    if message_type == 'text':
        opcode = WebSocketFrameHeader.OPCODE_TEXT
        data = os.urandom(length//2+1).hex()[:length].encode('ascii')
    else:
        opcode = WebSocketFrameHeader.OPCODE_BINARY
        data = os.urandom(length)

    print('sent length', len(data))
    if length < 100:
        print('sent data', data)

    _send_message(session, data, opcode)
    _receive_message(session)
    _close_websocket(session)


def probe(host, port, path, length, message_type='text', use_tls=False):
    """
    Send one message with specified length, and print the response message if any.
    """

    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as session:
                _handshake(session, host, port, path)
                _probe(session, length, message_type)

    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as session:
            session.connect((host, port))
            _handshake(session, host, port, path)
            _probe(session, length, message_type)
