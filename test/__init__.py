import asyncio

from functools import wraps

def websocket_filter(app):
	@wraps(app)
	async def wrapped(scope, receive, send):
		scope_type = scope['type']
		if scope_type == 'http':
			await send({
				'type': 'http.response.start',
				'status': 501,
				'headers': [
					[b'content-type', b'text/plain']
				]
			})
			await send({
				'type': 'http.response.body',
				'body': b''
			})
		else:
			await app(scope, receive, send)

	return wrapped

async def events(receive):
	running = True
	while running:
		msg = await receive()
		if msg is None:
			running = False
		elif msg['type'] == 'websocket.receive':
			yield msg
		elif msg['type'] == 'websocket.disconnect':
			running = False

class TestServer:
	async def __call__(self, scope, receive, send):
		await send({
			'type': 'websocket.accept'
		})

		async for event in events(receive):
			echo = event.copy()
			if echo.get('text', None) == 'close':
				await send({ 'type': 'websocket.close' })
				break

			echo['type'] = 'websocket.send'
			await send(echo)

test_server = websocket_filter(TestServer())