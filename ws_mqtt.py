"""
Async MQTT over WebSockets (MQTT 3.1.1) for MicroPython (ESP32) with debug logging
Handles Cloudflared WSS with proper SNI, and optional fallback to local WS for testing.
"""

import uasyncio as asyncio
import ubinascii
import urandom
import struct

# Import the AsyncWebsocketClient from your ws.py
try:
    from ws import AsyncWebsocketClient
except Exception as e:
    raise ImportError('ws.AsyncWebsocketClient required (the ws.py from micropython-async-websocket).')

# Helpers

def _encode_length(length):
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length > 0:
            digit |= 0x80
        encoded.append(digit)
        if length == 0:
            break
    return encoded


def _pack_str(s):
    b = s if isinstance(s, (bytes, bytearray)) else s.encode('utf-8')
    return struct.pack('>H', len(b)) + b

# MQTT WebSocket Client with debug and Cloudflared SNI handling
class MQTTWebSocketClient:
    def __init__(self, url, client_id=None, username=None, password=None, keepalive=60, ssl_params=None):
        self.url = url
        self.client_id = client_id or self._random_client_id()
        self.username = username
        self.password = password
        self.keepalive = keepalive
        self.ws = None
        self._packet_id = 1
        self._reader_task = None
        self._ping_task = None
        self._on_message = None
        self._connected = False
        self._ssl_params = ssl_params or {}

    def _random_client_id(self):
        r = ubinascii.hexlify(urandom.getrandbits(32).to_bytes(4, 'little'))
        return b'mp-' + r

    async def connect(self):

        if self.ws:
            try:
              await self.ws.close()
            except:
              pass
        
        print('Opening websocket to', self.url)
        self.ws = AsyncWebsocketClient()

        # Extract hostname from URL for proper SNI
        uri = self.ws.urlparse(self.url)
        hostname = uri.hostname
        print('Using hostname for TLS/SNI:', hostname)

        # TLS parameters
        cert_reqs = self._ssl_params.get('cert_reqs', 0)
        keyfile = self._ssl_params.get('keyfile', None)
        certfile = self._ssl_params.get('certfile', None)
        cafile = self._ssl_params.get('cafile', None)

        # Perform WebSocket handshake with proper SNI
        await self.ws.handshake(
            uri=self.url,
            keyfile=keyfile,
            certfile=certfile,
            cafile=cafile,
            cert_reqs=cert_reqs
        )

        print('Handshake done')

        # MQTT CONNECT packet
        con_pkt = self._build_connect()
        print('Sending CONNECT packet...')
        await self.ws.send(con_pkt)

        # Wait for CONNACK
        data = await self._recv_packet()
        print('Received CONNACK:', data)

        self._connected = True
        self._reader_task = asyncio.create_task(self._reader())
        self._ping_task = asyncio.create_task(self._keepalive_loop())

    async def disconnect(self):
        try:
            await self.ws.send(b'\xe0\x00')
        except Exception:
            pass
        self._connected = False
        if self._reader_task:
            self._reader_task.cancel()
        if self._ping_task:
            self._ping_task.cancel()
        try:
            await self.ws.close()
        except Exception:
            pass

    def set_callback(self, cb):
        self._on_message = cb

    async def publish(self, topic, payload, retain=False):
        print('Publishing to topic:', topic, 'payload:', payload)
        if not isinstance(topic, (bytes, bytearray)):
            topic = topic.encode('utf-8')
        if not isinstance(payload, (bytes, bytearray)):
            payload = payload.encode('utf-8')
        fixed = 0x30 | (0x01 if retain else 0)
        variable = _pack_str(topic) + payload
        remaining = _encode_length(len(variable))
        packet = bytes([fixed]) + remaining + variable
        await self.ws.send(packet)

    async def subscribe(self, topic):
        print('Subscribing to topic:', topic)
        if not isinstance(topic, (bytes, bytearray)):
            topic = topic.encode('utf-8')
        packet_id = self._next_packet_id()
        variable = struct.pack('>H', packet_id) + _pack_str(topic) + bytes([0])
        fixed = 0x82
        remaining = _encode_length(len(variable))
        packet = bytes([fixed]) + remaining + variable
        await self.ws.send(packet)

    # Internal helpers
    def _next_packet_id(self):
        pid = self._packet_id
        self._packet_id += 1
        if self._packet_id > 0xFFFF:
            self._packet_id = 1
        return pid

    def _build_connect(self):
        proto = _pack_str('MQTT') + bytes([4])
        flags = 0x02  # clean session
        if self.username:
            flags |= 0x80
        if self.password:
            flags |= 0x40
        keep = struct.pack('>H', self.keepalive)
        variable_header = proto + bytes([flags]) + keep
        payload = _pack_str(self.client_id)
        if self.username:
            payload += _pack_str(self.username)
        if self.password:
            payload += _pack_str(self.password)
        remaining = _encode_length(len(variable_header) + len(payload))
        return bytes([0x10]) + remaining + variable_header + payload

    async def _recv_packet(self):
        data = await self.ws.recv()
        #print('Raw packet received:', data)
        return data

    def _decode_length(self, data, start):
        multiplier = 1
        value = 0
        idx = start
        while True:
            digit = data[idx]
            value += (digit & 127) * multiplier
            multiplier *= 128
            idx += 1
            if (digit & 128) == 0:
                break
        return value, idx

    async def _reader(self):
        try:
            while True:
                data = await self._recv_packet()
                if not data:
                    self._connected = False
                    break
                offset = 0
                L = len(data)
                while offset < L:
                    fh = data[offset]
                    packet_type = fh >> 4
                    rem_len, rem_index = self._decode_length(data, offset + 1)
                    payload_start = rem_index
                    end = payload_start + rem_len
                    pkt = data[offset:end]
                    if packet_type == 3:
                        await self._handle_publish(pkt)
                    offset = end
        except asyncio.CancelledError:
            return
        except Exception as e:
            print('Reader error:', e)
            self._connected = False

    async def _handle_publish(self, pkt):
        rem_len, rem_index = self._decode_length(pkt, 1)
        topic_len = struct.unpack('>H', pkt[rem_index: rem_index + 2])[0]
        topic = pkt[rem_index + 2: rem_index + 2 + topic_len]
        pos = rem_index + 2 + topic_len
        payload = pkt[pos: rem_index + rem_len]
        #print('Received PUBLISH:', topic, payload)
        if self._on_message:
            asyncio.create_task(self._on_message(topic, payload))

    async def _keepalive_loop(self):
        try:
            while True:
                await asyncio.sleep(self.keepalive)
                if not self._connected:
                    break
                try:
                    print('Sending PINGREQ')
                    await self.ws.send(b'\xC0\x00')
                except Exception:
                    self._connected = False
                    break
        except asyncio.CancelledError:
            return
