Sloth
=====

`Sloth` is a DoS attack tool similar to `Slowloris`.

Currently only implemented WebSocket attack, but the same mechanism may also
apply to other TCP based protocols.

## How it works

The WebSocket protocol builds a message layer on
top of TCP. Each message contains a header and payload data. The header has a
`length` field, it defines the payload length. The WebSocket server may read
the header from TCP, get the length, and then read `length` bytes from TCP,
then deliver the payload to upper application. When the payload is only
partially read, the server may buffer the data in memory, and wait all to
arrive. This is where the vulnerability is. To prevent attack, the server
may limit the max message size. If the `length` field in the header is bigger
than the limit, the server can simply close the connection.

But if the limit is high, we can still attack it with a large number of
connections. In each connection, we send a header with a `length` that's a
little bit less than the limit. Then we send most of the payload, not the
full payload, so this part will left in the server's memory, and won't be 
delivered. To keep the connection alive, we then send the rest of payloay
at a very low speed, just like Slow and Low Attack.

This tool can efficiently send a large number of connections while use a small
amount of resources. On my test machine, 1000 connections only used 60MB of
memory on client side, and ate more than 6GB on server side.

## Usage

This script is built on `asyncio`, it requires Python 3.6+.

To `probe` is to send a random message with the specified length to the target
URL, and print out the response if there is any. If the TCP connection is reset or broken, it's
probably that the target URL does not allow this size of message.

```sh
# probe with 11KB of data
python3 main.py --target https://example.com/resource --length 11000 --probe
```

To `attack` is to open a large number of connections and send a partial message
with each connection.

```sh
# open 1000 connections, each send 10MB of data, 10 new connections per second
python3 main.py --target https://example.com/resource --length 10000000 --attack --session 1000 --rate 10
```
