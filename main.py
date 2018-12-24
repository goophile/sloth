#!/usr/bin/env python3

import argparse
from urllib.parse import urlparse

from sloth.websocket_probe import probe
from sloth.websocket_attack import attack


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
    parser = argparse.ArgumentParser(description='Slow and low TCP attack')

    parser.add_argument('--target', required=True, help='IP or domain of the target host.')
    parser.add_argument('--probe', action='store_true', help='Try send one message with the specified length.')
    parser.add_argument('--attack', action='store_true', help='Send flood messages with the specified length.')
    parser.add_argument('--type', default='text', choices=['text', 'binary'], help='Message type, text or binary.')
    parser.add_argument('--length', help='Length of each message in bytes.')
    parser.add_argument('--number', help='Parallel session numbers for attack.')
    args = parser.parse_args()

    use_tls, host, port, path = _parse_url(args.target)

    if args.probe:
        probe(host, port, path, int(args.length), args.type, use_tls)

    if args.attack:
        attack(host, port, path, int(args.length), int(args.number), args.type, use_tls)


if __name__ == '__main__':
    main()
