import asyncio
import lib
import threading
import time
import sys

from tkinter import Tk
from app import Sockman

ctx = lib.websocket.WebSocketContext()

async def main():
	root = Tk()
	root.minsize(200, 150)

	should_stop = threading.Event()
	def stop():
		app.finish()
		should_stop.set()

	app = Sockman(root, ctx, stop)
	root.protocol('WM_DELETE_WINDOW', stop)

	while not should_stop.is_set():
		try:
			root.update()
			root.update_idletasks()
			await asyncio.sleep(0.05) # allow for async stuff to run
		except asyncio.CancelledError:
			should_stop.set()

	root.destroy()

ctx.run(main())