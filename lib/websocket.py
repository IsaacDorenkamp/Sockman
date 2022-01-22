import asyncio
from io import StringIO, BytesIO

import atexit
import base64
import hashlib
import os
import re
import select
import socket
import ssl
import struct
import sys
import threading
import time

from datetime import datetime, timedelta
from enum import Enum
from queue import Queue

from .http import *

import weakref

class BlockingError(Exception):
	def __init__(self):
		Exception.__init__(self, "Socket would block")

def gen_ws_key():
	return base64.b64encode(os.urandom(16)).decode('ascii')

def read_until(sock, until, buf_size=1024):
	rec = []
	chunk = BytesIO()
	while bytes(rec[-len(until):]) != until:
		try:
			octet = sock.recv(1)
			if octet == b'':
				# connection has been closed
				return
		except:
			continue

		chunk.write(octet)
		if chunk.getbuffer().nbytes == buf_size:
			yield bytes(chunk.getbuffer())
			chunk = BytesIO()

		rec.append(octet[0])
		if rec[-len(until):] == until:
			return

	if chunk.getbuffer().nbytes > 0:
		yield bytes(chunk.getbuffer())

class WebSocketContext:

	DEFAULT_TIMEOUT = 30

	def __init__(self):
		self._socks = weakref.WeakSet()
		self._running = False

		atexit.register(self.cleanup)

	def register(self, sock):
		assert isinstance(sock, WebSocket), TypeError("sock must be a WebSocket!")
		self._socks.add(sock)

	def __del__(self):
		self.cleanup()
		atexit.unregister(self.cleanup)

	def cleanup(self):
		for sock in filter(lambda s: s.state == WebSocket.State.OPEN, self._socks):
			sock.close()

	async def loop(self):
		check = 0
		while self._running:
			now = datetime.now()
			# temporarily create strong references to all sockets
			all_socks = tuple(filter(lambda sock: sock.state == WebSocket.State.OPEN, self._socks))
			sock = None # to fix UnboundLocalError caused when no sockets are created
			for sock in all_socks:
				check += 1
				await sock._receive_all()
				should_ping = (sock._last_sent + timedelta(seconds=sock.timeout)) < now
				if should_ping:
					await sock.ping()
			
			# delete all strong references to sockets to allow them
			# to be removed from the weakset if applicable
			del sock
			del all_socks

			await asyncio.sleep(0.05)

	@property
	def nsockets(self):
		return len(self._socks)

	def run(self, coro):
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)

		self._running = True

		async def wrapped():
			await coro
			self._running = False

		async def mainloop():
			app = loop.create_task(wrapped())
			receiver = loop.create_task(self.loop())
			tasks = [app, receiver]
			done = False
			while not done:
				done = any(map(lambda task: task.done(), tasks))
				await asyncio.sleep(0.05)

			for task in tasks:
				if not task.done():
					task.cancel()
				else:
					exc = task.exception()
					if exc is not None:
						raise exc

		loop.run_until_complete(mainloop())

	def create_socket(self, uri, timeout, verify=True, headers={}, mode=None):
		if mode is None:
			mode = WebSocket.Mode.BUFFER
		return WebSocket(self, uri, timeout, verify=verify, headers=headers, mode=mode)

class WebSocket:

	class Closed(Exception):
		def __init__(self, msg="WebSocket closed"):
			Exception.__init__(self, msg)

	class State(Enum):
		CONNECTING = 0
		OPEN = 1
		CLOSING = 2
		CLOSED = 3

	class Mode(Enum):
		BUFFER = 0
		EVENT = 1

	GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	FINAL_BIT = 0b10000000

	TEXT_FRAME   = 0x1
	BINARY_FRAME = 0x2
	DATA_FRAME_OPCODES = [TEXT_FRAME, BINARY_FRAME]

	MASK_BIT = 0b10000000
	MASK_LENGTH = 4

	OPCODE_CLOSE = 0x8
	OPCODE_PING = 0x9
	OPCODE_PONG = 0xA

	WEBSOCKET_URI_RE = r'(wss?)://([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)(?::([0-9]{1,5}))?((?:/[A-Za-z0-9-_.~!$&\'()*+,;=:@%]+)*/?)?$'
	@staticmethod
	def parse_uri(ws_uri):
		if not isinstance(ws_uri, str):
			raise TypeError("URI must be a string!")
		
		m = re.match(WebSocket.WEBSOCKET_URI_RE, ws_uri)
		if m is None:
			raise ValueError(f"Invalid WebSocket URI '{ws_uri}'")
		else:
			secure = m.group(1) == 'wss'
			addr = m.group(2)
			port = int(m.group(3) or ("443" if secure else "80"))
			endpoint = m.group(4) or '/'
			return secure, addr, port, endpoint

	def __init__(self, context, uri, timeout, verify=True, headers={}, mode=Mode.BUFFER):
		assert isinstance(context, WebSocketContext), TypeError("Context must be a WebSocketContext instance!")
		context.register(self)
		self._ctx = context

		secure, addr, port, endpoint = WebSocket.parse_uri(uri)

		self._mode = mode

		if mode == WebSocket.Mode.BUFFER:
			self._buffer = Queue()
		else:
			self._handlers = {
				'message': [],
				'close': [],
				'ping': []
			}

		self.uri = uri

		self._state = WebSocket.State.CONNECTING

		self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._sock.connect((addr, port))

		self._addr = addr
		self._port = port

		self._secure = secure
		if secure:
			ctx = ssl.create_default_context()
			if not verify:
				ctx.check_hostname = False
				ctx.verify_mode = ssl.CERT_NONE
			self._sock = ctx.wrap_socket(self._sock, server_hostname=addr)

		# timeout
		self._timeout = timeout
		self._last_sent = datetime.now()

		try:
			self._handshake(endpoint, headers)
		except ValueError:
			self._state = WebSocket.State.CLOSED
			self._sock.close()
			raise

	def __del__(self):
		if self._state == WebSocket.State.OPEN:
			self.close()

	@property
	def timeout(self):
		return self._timeout

	@property
	def state(self):
		return self._state

	@property
	def address(self):
		return self._addr

	@property
	def port(self):
		return self._port

	@property
	def secure(self):
		return self._secure

	def handler(self, handler, handler_type='message'):
		if self._mode == WebSocket.Mode.EVENT:
			self._handlers[handler_type].append(handler)
		else:
			raise ValueError("WebSocket is not in EVENT mode.")

	def unset_handler(self, handler, handler_type='message'):
		if self._mode == WebSocket.Mode.EVENT:
			if handler in self._handlers[handler_type]:
				self._handlers[handler_type].remove(handler)
			else:
				raise ValueError("No such handler registered for event type '%s'" % handler_type)
		else:
			raise ValueError("WebSocket is not in EVENT mode.")

	def _handshake(self, endpoint, headers):
		self._sock.setblocking(True)
		ws_key = gen_ws_key()

		headers = headers.copy()
		headers.update({
			"Host": self._addr,
			"Upgrade": "websocket",
			"Connection": "Upgrade",
			"Sec-WebSocket-Key": ws_key,
			"Sec-WebSocket-Version": "13"
		})
		req = HttpRequest("get", endpoint, headers)
		for line in req:
			self._sock.sendall(line)

		data = BytesIO()
		for chunk in read_until(self._sock, b'\r\n\r\n'):
			data.write(chunk)

		raw_res = bytes(data.getbuffer()).decode('ascii')[:-4] # exclude double CRLF
		res = HttpResponse.parse(raw_res)

		if res.status != 101:
			# handshake failed
			raise ValueError(f"Server responded with unexpected status code {res.status}.")
		else:
			upgrade = res.headers.get('upgrade', '')
			if upgrade.lower() != 'websocket':
				raise ValueError(f"upgrade header in response not a match for 'websocket' (got '{upgrade}').")

			if not any(map(lambda token: token.lower() == 'upgrade', res.headers.get('connection', '').split(' '))):
				raise ValueError(f"connection header in response did not contain an 'upgrade' token.")

			accept = res.headers.get('sec-websocket-accept', '')

			hasher = hashlib.new('SHA1')
			hasher.update(ws_key.encode())
			hasher.update(WebSocket.GUID.encode())
			expected = base64.b64encode(hasher.digest()).decode('ascii')
			if accept != expected:
				raise ValueError(f"invalid sec-websocket-accept header (expected '{expected}', got '{accept}').")
			else:
				self._state = WebSocket.State.OPEN
				self._last_sent = datetime.now()

	def _create_frame(self, data, opcode, final):
		initial_byte = (WebSocket.FINAL_BIT if final else 0) | opcode

		mask_and_payload = 0
		mask_and_payload |= WebSocket.MASK_BIT

		extended = b''

		size = len(data)
		if size < 126:
			mask_and_payload |= size
		elif size <= 65535:
			mask_and_payload |= 126
			extended = struct.pack('>H', size)
		elif size <= 18446744073709551615:
			mask_and_payload |= 127
			extended = struct.pack('>Q', size)
		else:
			raise ValueError("Frame data too large!")

		frame = BytesIO()
		frame.write(bytes([initial_byte, mask_and_payload]) + extended)

		mask_key = os.urandom(WebSocket.MASK_LENGTH)
		frame.write(mask_key)

		masked = bytes([data[i] ^ mask_key[i % len(mask_key)] for i in range(size)])
		frame.write(masked)

		return bytes(frame.getbuffer())

	async def _do_send(self, raw_data):
		sent = 0
		size = len(raw_data)
		while sent < size:
			_, w, _ = select.select([], [self._sock], [], 0)
			if self._sock in w:
				to_send = raw_data[sent:]
				sent += self._sock.send(to_send)
			else:
				await asyncio.sleep(0.005)

	async def send(self, data, opcode=None, max_frame_size=(1024 * 32), on_progress=None):
		if self._state != WebSocket.State.OPEN:
			raise ValueError("WebSocket is not in the OPEN state.")

		if opcode is None:
			if isinstance(data, str):
				mtype = WebSocket.TEXT_FRAME
				data = data.encode()
			elif isinstance(data, bytes):
				mtype = WebSocket.BINARY_FRAME
			else:
				raise TypeError(f"Invalid data type '{type(data)}'")
		else:
			if not isinstance(data, bytes):
				raise TypeError(f"data must be a bytes object when opcode is specified")

			mtype = opcode

		def progress_cbk(progress):
			if callable(on_progress):
				on_progress(progress)

		total_data = len(data)
		full_frames = total_data // max_frame_size
		sent_final = False
		frame_op = mtype
		for i in range(full_frames):
			sent_final = (i + 1) * max_frame_size >= total_data
			frame = self._create_frame(data[(i * max_frame_size):((i + 1) * max_frame_size)], frame_op, sent_final)
			if frame_op != 0:
				frame_op = 0
			await self._do_send(frame)
			progress_cbk(((i + 1) * max_frame_size) / total_data)
			self._last_sent = datetime.now()

		if not sent_final:
			last_frame = self._create_frame(data[full_frames * max_frame_size:], frame_op, True)
			await self._do_send(last_frame)
			progress_cbk(1.0)
			self._last_sent = datetime.now()

	async def ping(self, data=None):
		if data is None:
			data = bytes()
		await self.send(data, opcode=WebSocket.OPCODE_PING)

		for handler in self._handlers['ping']:
			handler()

	def _fail(self, msg):
		self._sock.close()
		raise ValueError(msg)

	async def _recv_all(self, amount):
		_block = self._sock.getblocking()
		self._sock.setblocking(False)
		res = BytesIO()
		received = 0

		check = 0
		while received < amount:
			remaining = amount - received
			try:
				chunk = self._sock.recv(remaining)
				received += len(chunk)
				res.write(chunk)
			except:
				await asyncio.sleep(0.05)
		self._sock.setblocking(_block)

		return bytes(res.getbuffer())

	async def _recv_frame(self, block=True):
		self._sock.setblocking(block)
		try:
			signature = await self._recv_all(2)
			if signature == b'':
				raise WebSocket.Closed()
		except ssl.SSLError as err:
			if err.errno == ssl.SSL_ERROR_WANT_READ:
				raise BlockingError()

		start_byte = signature[0]
		fin = (start_byte & WebSocket.FINAL_BIT) != 0

		rsv = start_byte & 0b01110000
		if rsv != 0:
			self._fail("Server sent frame with non-zero RSV bits!")

		opcode = start_byte & 0b1111

		mask_and_len = signature[1]
		mask = (mask_and_len & WebSocket.MASK_BIT) != 0
		if mask:
			self._fail("Server should not send masked frames!")

		payload_len = mask_and_len & 0b01111111
		if payload_len < 126:
			to_recv = payload_len
		elif payload_len == 126:
			to_recv = struct.unpack('>H', self._sock.recv(2))[0]
		else:
			# payload_len *must* be 127 in this case
			to_recv = struct.unpack('>Q', self._sock.recv(8))[0]

		payload = await self._recv_all(to_recv)
		frame = {
			'final': fin,
			'opcode': opcode,
			'control': (opcode & 0b1000) != 0,
			'payload': payload
		}
		return frame

	async def receive(self):
		if self._mode != WebSocket.Mode.BUFFER:
			raise ValueError("Websocket is not in BUFFER mode.")

		while True:
			try:
				return self._buffer.get_nowait()
			except:
				await asyncio.sleep(0.05)

	def can_receive(self):
		if self._mode == WebSocket.Mode.BUFFER:
			return not self._buffer.empty()
		else:
			return False

	async def _receive_all(self):
		recving = True
		while recving:
			try:
				await self._receive(False)
			except BlockingError as err:
				recving = False
			except WebSocket.Closed:
				recving = False

	async def _receive(self, block=True):
		frame = await self._recv_frame(block)
		opcode = frame['opcode']
		if frame['control']:
			self._handle_control(frame)
		else:
			if opcode == 0:
				self._fail("Server sent a continuation frame that doesn't belong to a message!")
			if opcode not in WebSocket.DATA_FRAME_OPCODES:
				self._fail(f"Server sent data frame with invalid opcode {opcode}")

			payload = BytesIO()
			payload.write(frame['payload'])
			final = frame['final']
			while not final:
				frame = await self._recv_frame()
				if frame['control']:
					self._handle_control(frame)
				else:
					if frame['opcode'] != 0:
						self._fail("Server didn't send a continuation frame as expected!")

					payload.write(frame['payload'])
					final = frame['final']

			raw = bytes(payload.getbuffer())
			if opcode == WebSocket.TEXT_FRAME:
				try:
					msg = {
						'type': opcode,
						'text': raw.decode('utf-8')
					}
				except UnicodeDecodeError:
					self._fail("Server sent message with invalid Unicode data!")
			else:
				# WebSocket.BINARY_FRAME
				msg = {
					'type': opcode,
					'binary': raw
				}

			if self._mode == WebSocket.Mode.BUFFER:
				self._buffer.put_nowait(msg)
			else:
				# EVENT mode
				for handler in self._handlers['message']:
					handler(msg)

	def _handle_control(self, frame):
		if not frame['final']:
			self._fail("Server sent a control frame without the final bit set!")

		opcode = frame['opcode']
		if opcode == WebSocket.OPCODE_CLOSE:

			if self._state == WebSocket.State.CLOSING:
				# close is mutual, we may close our socket according to the RFC.
				self._sock.close()
			else:
				# state is CLOSED
				self.close()
			raise WebSocket.Closed()
		elif opcode == WebSocket.OPCODE_PING:
			self.send(bytes(), opcode=WebSocket.OPCODE_PONG)
		elif opcode == WebSocket.OPCODE_PONG:
			# TODO: use PONGs to monitor keepalive?
			pass
		else:
			self._fail(f"Received unknown opcode {hex(opcode)}")

	def close(self, status_code=1000):
		if self._state == WebSocket.State.OPEN:
			# synchronously send the frame - should not be async
			frame = self._create_frame(struct.pack('>H', status_code), WebSocket.OPCODE_CLOSE, True)
			sent = False
			while not sent:
				r, w, x = select.select([], [self._sock], [], 0)
				if self._sock in w:
					self._sock.sendall(frame)
					sent = True

			for handler in self._handlers['close']:
				handler(status_code)

			self._state = WebSocket.State.CLOSING
		else:
			raise ValueError("WebSocket is not in OPEN state.")