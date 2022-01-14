from io import StringIO
import re

class HttpRequest:

	PATH_RE = r'^(/[A-Za-z0-9-_.~!$&\'()*+,;=:@%]*)(/[A-Za-z0-9-_.~!$&\'()*+,;=:@%]+)*/?$'
	HEADER_RE = r'^([a-zA-Z_-]+): (.+)$'

	HTTP_VERSION = "1.1"
	METHODS = ["GET", "POST", "DELETE", "PATCH", "PUT", "HEAD", "OPTIONS"]

	def __init__(self, method, path, headers={}):
		method = method.upper()
		if method not in HttpRequest.METHODS:
			raise ValueError("method must be a valid HTTP verb")

		self._meth = method
		if re.match(HttpRequest.PATH_RE, path) is None:
			raise ValueError("path must be valid HTTP path")

		self._path = path

		for key in headers.keys():
			value = headers[key]
			header_line = f'{key}: {value}'
			if re.match(HttpRequest.HEADER_RE, header_line) is None:
				raise ValueError(f"the header '{key}' has an invalid name or value")

		self._headers = headers.copy()

	def __iter__(self):
		yield f"{self._meth} {self._path} HTTP/{HttpRequest.HTTP_VERSION}\r\n".encode()
		for key in self._headers.keys():
			yield f"{key}: {self._headers[key]}\r\n".encode()
		yield "\r\n".encode()

	def __str__(self):
		s = StringIO()
		for line in self:
			s.write(line)
		return s.getvalue()

	@staticmethod
	def make_headers(data, line_delim='\r\n'):
		return line_delim.join([f'{key}: {val}' for (key, val) in data.items()])

class HttpResponse:

	STATUS_LINE_RE = r'^HTTP/1\.1 ([0-9]{3}) ([A-Za-z ]+)?$'

	def __init__(self, status, headers={}, status_nick=None):
		self._status = status
		self._status_nick = status_nick
		self._headers = headers

	@property
	def status(self):
		return self._status

	@property
	def headers(self):
		return self._headers.copy()

	def __str__(self):
		return f"<Response {self._status}>"

	def __repr__(self):
		out = StringIO()
		out.write(f"HTTP/1.1 {self.status} {self._status_nick or ''}\r\n")
		for header in self._headers.keys():
			out.write(f"{header}: {self._headers[header]}\r\n")
		out.write("\r\n")
		return out.getvalue()

	@staticmethod
	def parse(raw_res):
		parts = raw_res.split('\r\n')
		status_line = parts[0]
		line_match = re.match(HttpResponse.STATUS_LINE_RE, status_line)
		if line_match is None:
			raise ValueError("Invalid HTTP response")

		status = int(line_match.group(1))
		headers = {}
		for line in parts[1:]:
			name, value = line.split(': ', 2)
			headers[name.lower()] = value

		return HttpResponse(status, headers=headers, status_nick=line_match.group(2))