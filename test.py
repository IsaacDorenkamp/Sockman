import lib

import sys
import unittest

class TestHttpRequest(unittest.TestCase):
	def setUp(self):
		self.request_a = lib.HttpRequest("get", "/")
		self.request_b = lib.HttpRequest("get", "/", {
			"Connection": "Upgrade",
			"Upgrade": "websocket"
		})

	def testStr(self):
		self.assertEqual(str(self.request_a), """GET / HTTP/1.1\r\n\
\r\n""")

	def testParseURI(self):
		secure, addr, port, endpoint = lib.WebSocket.parse_uri("wss://sub.domain.com:321/chat/subchat")
		self.assertTrue(secure)
		self.assertEqual(addr, "sub.domain.com")
		self.assertEqual(port, 321)
		self.assertEqual(endpoint, "/chat/subchat")

if __name__ == '__main__':
	unittest.main()