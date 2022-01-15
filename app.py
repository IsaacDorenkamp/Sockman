from tkinter import *
from tkinter import ttk
from tkinter import commondialog
from tkinter import filedialog

from lib.websocket import *
from lib.http import HttpRequest
from datetime import datetime, timedelta

import asyncio
import base64
import functools
import json
import os
import re
import time
import uuid

import warnings

global style
style = None

def parse_geometry(geo):
	parts = geo.split('+')
	size = [int(i) for i in parts[0].split('x')]
	pos = [int(i) for i in parts[1:]]
	return size, pos

def load_theme(root, name, version=1.0):
	path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'themes')
	root.tk.eval(f"""\
set base_theme_dir {path}/

package ifneeded ttk::theme::{name} {version} \
	[list source [file join $base_theme_dir {name} {name}.tcl]]
""")
	root.tk.call("package", "require", f"ttk::theme::{name}")

def setup_style(root, background='#ddd'):
	global style
	if style is None:
		# Load external themes
		load_theme(root, 'arc', 0.1)

		style = ttk.Style(root)

		# Use loaded theme
		style.theme_use('arc')

		style.configure('TFrame', background='white')
		style.configure('Fill.TFrame', background=background)
		style.configure('TLabel', background=background)
		style.configure('TButton', bordercolor='#ccc', background=background)
		style.configure('Highlight.TFrame', background='blue')
		style.configure('Toolbar.TFrame', background=background)
		style.configure('TEntry', insertcolor='black')
		style.configure('Error.TEntry', fieldbackground='#ff6961', foreground='white', insertcolor='white')

		style.map('Delete.TButton', background=[('!active', '#ff6961'), ('active', 'red')],
			foreground=[('!active', 'white'), ('active', 'white')],
			borderwidth=[('!active', '0'), ('active', '0')])

		style.configure('Fill.TFrame', background=background)

		style.configure('Status.TLabel', bordercolor='#ccc', background='white')
		style.configure('Error.Status.TLabel', foreground='red')
		style.configure('Success.Status.TLabel', foreground='green')

		style.configure('TProgressbar', background='#7d7')

		style.configure('About.TLabel', foreground='black')

version_file = os.path.join(os.path.dirname(__file__), 'VERSION.txt')
version = None
def get_version():
	global version
	if version is None:
		with open(version_file, 'r') as fp:
			version = fp.read()
	
	return version

def start(fn):
	def newfn(*args, **kwargs):
		loop = asyncio.get_running_loop()
		loop.create_task(fn(*args, **kwargs))
	return newfn

class AboutDialog(Toplevel):
	def __init__(self, master):
		Toplevel.__init__(self, master)
		self._build()

	def _build(self):
		self.title("About Sockman")
		self.resizable(False, False)
		frame = ttk.Frame(self, style='Fill.TFrame')

		frame.columnconfigure(0, weight=1)
		frame.rowconfigure(1, weight=1)

		top = ttk.Label(frame, text=f"Sockman v{get_version()}",
			anchor='center', font=('Arial', 16), style='Head.About.TLabel')

		desc = ttk.Label(frame, text=f"""\
    Sockman is a utility developed by Isaac Dorenkamp \
for the purpose of having a dedicated WebSocket client \
tool to test server applications with. It is available for \
use free-of-charge with no restrictions. Happy testing!
""", anchor='nw', wraplength=300, style='About.TLabel')

		top.grid(row=0, column=0, sticky='nesw', ipadx=5, ipady=5)
		desc.grid(row=1, column=0, sticky='nesw', padx=10)
		ttk.Button(frame, text="OK", command=self._close).grid(row=2, column=0, padx=5, pady=(0, 5))

		frame.pack(expand=True, fill='both')

	def _close(self, *_):
		self.destroy()

class ConnectDialog(Toplevel):

	LABEL_FONT = ('Arial', 14)

	def __init__(self, master):
		Toplevel.__init__(self, master)

		self._ok = False
		self._build()

	def _build(self):
		self.title("Connect")

		self.url = StringVar()

		self.frame = ttk.Frame(self, style='Fill.TFrame')
		self.columnconfigure(0, weight=1)
		self.rowconfigure(0, weight=1)
		self.frame.grid(row=0, column=1, sticky='nesw')

		self.frame.rowconfigure(1, weight=1)
		self.frame.columnconfigure(2, weight=1)

		ttk.Label(self.frame, text="WebSocket URL", style='Fill.TLabel', font=ConnectDialog.LABEL_FONT).grid(row=0, column=0, sticky='e', padx=3)
		self._url = entry = ttk.Entry(self.frame, textvariable=self.url)
		entry.grid(row=0, column=1, sticky='nesw', padx=5, pady=5, ipadx=5, ipady=5)
		entry.bind("<Return>", self._try_close)
		ttk.Button(self.frame, text="OK", command=self._try_close, width=4).grid(row=2, column=2, sticky='e', padx=5, pady=5)

		# header key-val input
		self.headers = ttk.Frame(self.frame, style='Fill.TFrame')
		self.headers.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='we')

		self.headers.columnconfigure(0, weight=0)
		self.headers.columnconfigure(1, weight=1)
		self.headers.columnconfigure(2, weight=0)

		ttk.Label(self.headers, text="Headers", style='Fill.TLabel', font=ConnectDialog.LABEL_FONT).grid(row=0, column=0, columnspan=2, sticky='w')

		self._headers = {}

		self._key = StringVar()
		self._key_ent = ttk.Entry(self.headers, textvariable=self._key, width=10)
		self._key_ent.grid(row=1, column=0, ipadx=3, ipady=3, sticky='we')

		self._val = StringVar()
		self._val_ent = ttk.Entry(self.headers, textvariable=self._val)
		self._val_ent.grid(row=1, column=1, ipadx=3, ipady=3, padx=(5, 0), sticky='we')

		self._val_ent.bind('<Return>', self.add_header)

		self._add = ttk.Button(self.headers, text="Add", command=self.add_header, width=4)
		self._add.grid(row=1, column=2, padx=5, pady=5, sticky='e')

	def add_header(self, _=None):
		key = self._key.get()
		val = self._val.get()

		valid = re.match(HttpRequest.HEADER_RE, f'{key}: {val}') is not None
		if not valid:
			self._key_ent.configure(style="Error.TEntry")
			self._val_ent.configure(style="Error.TEntry")
			return
		else:
			self._key_ent.configure(style="TEntry")
			self._val_ent.configure(style="TEntry")

		if key in self._headers:
			self._headers[key][1].set(self._val.get())
		else:
			key_var = StringVar()
			val_var = StringVar()

			key_var.set(key + ':')
			val_var.set(self._val.get())

			key_lbl = ttk.Label(self.headers, textvariable=key_var, style='Table.TLabel', anchor='e')
			var_lbl = ttk.Label(self.headers, textvariable=val_var, style='Table.TLabel', anchor='w')
			del_btn = ttk.Button(self.headers, text="\u00d7", width=2, style='Delete.TButton',
				command=functools.partial(self.delete_header, key))
			self._headers[key] = (key_var, val_var, key_lbl, var_lbl, del_btn)
			self.fix_headers()

			self._key.set('')
			self._val.set('')

			self._key_ent.focus()

	def delete_header(self, key):
		head = self._headers[key]
		for i in range(2, 5):
			head[i].grid_forget()

		del self._headers[key]

		self.fix_headers()

	def fix_headers(self):
		for header in self._headers.values():
			header[2].grid_forget()
			header[3].grid_forget()

		i = 2 # first row of header descriptions
		for _k in sorted(self._headers.keys()):
			header = self._headers[_k]
			header[2].grid(row=i, column=0, sticky='nesw', ipadx=5, ipady=5)
			header[3].grid(row=i, column=1, sticky='nesw', ipadx=5, ipady=5)
			header[4].grid(row=i, column=2, sticky='w')
			i += 1

	def _try_close(self, *_):
		url = self.url.get()
		try:
			WebSocket.parse_uri(url)
			self._close()
		except ValueError:
			self._url.configure(style="Error.TEntry")

	def _close(self):
		self._ok = True
		self.destroy()

	def get_headers(self):
		out = {}
		for key in self._headers:
			out[key] = self._headers[key][1].get()
		return out

	@property
	def ok(self):
		return self._ok

class ProgressDialog(Toplevel):
	def __init__(self, master):
		Toplevel.__init__(self, master)
		self._build()

	def _build(self):
		self.geometry('175x45')

		self._frame = ttk.Frame(self)
		self._prog = ttk.Progressbar(self._frame, orient='horizontal', length=100, mode='determinate')

		self.columnconfigure(0, weight=1)
		self.rowconfigure(0, weight=1)
		self._frame.grid(row=0, column=0, ipadx=10, ipady=10, sticky='nesw')
		self._prog.pack(expand=True, fill='both')

		self.focus()
		self.grab_set()
		self.protocol('WM_DELETE_WINDOW', lambda: None)

	def update_progress(self, newval):
		if newval == 1.0:
			self.destroy()
		else:
			self._prog['value'] = int(newval * 100)

class JsonView(ttk.Frame):
	def __init__(self, master):
		ttk.Frame.__init__(self, master)

		self._raw = None
		self._data = None
		self._dirty = True

		self._build()

	def _build(self):
		self._table = ttk.Treeview(self)
		self._table['columns'] = ('key', 'value')

		self.columnconfigure(0, weight=1)
		self.rowconfigure(1, weight=1)
		self._table.grid(row=1, column=0, sticky='nesw')

		# configure the tree column to be hidden
		self._table.column('#0', width=0, stretch=False)
		self._table.heading('#0', text='', anchor='center')

		self._table.column('key', anchor='center', stretch=True)
		self._table.column('value', anchor='center', stretch=True)

		self._table.heading('key', text='Key')
		self._table.heading('value', text='Value')

		# inputs
		self._input = ttk.Frame(self, style="Fill.TFrame")
		self._key = StringVar()
		self._value = StringVar()

		self.key = ttk.Entry(self._input, textvariable=self._key)
		self.value = ttk.Entry(self._input, textvariable=self._value)
		self.put = ttk.Button(self._input, text="Enter", command=self.add_item)

		self.value.bind("<Return>", self.on_return)

		self._input.columnconfigure(0, weight=1)
		self._input.columnconfigure(1, weight=1)
		self._input.grid(row=0, column=0, sticky='nesw')
		self.key.grid(row=0, column=0, sticky='nesw', padx=5, pady=5)
		self.value.grid(row=0, column=1, sticky='nesw', padx=5, pady=5)
		self.put.grid(row=0, column=2, sticky='nesw', padx=5, pady=5)

	def on_return(self, *_):
		self.add_item()
		self._key.set('')
		self._value.set('')

	def add_item(self):
		key, value = self._key.get(), self._value.get()

		if not key:
			return

		if key in self.get_raw_data().keys():
			self._table.item(key, values=(key, value))
		else:
			self._table.insert(parent='', index='end', text='', iid=key, values=(self._key.get(), self._value.get()))

		self._dirty = True

	def get_data(self):
		if self._dirty:
			out = {}
			for child in self._table.get_children():
				item = self._table.item(child)
				key, value = item['values']
				out[key] = value
			self._raw = out
			self._data = json.dumps(out)
			self._dirty = False

		return self._data

	def get_raw_data(self):
		self.get_data()
		return self._raw

	def reset(self):
		self._data = None
		self._dirty = True
		self._table.delete(*self._table.get_children())

		self._key.set('')
		self._value.set('')

class TextView(ttk.Frame):
	def __init__(self, master):
		ttk.Frame.__init__(self, master)
		self._build()

	def _build(self):
		self._yscroll = ttk.Scrollbar(self)
		self._xscroll = ttk.Scrollbar(self, orient='horizontal')
		self._text = Text(self, yscrollcommand=self._yscroll.set, xscrollcommand=self._xscroll.set, wrap="none")
		self._yscroll.configure(command=self._text.yview)
		self._xscroll.configure(command=self._text.xview)

		self.columnconfigure(0, weight=1)
		self.rowconfigure(0, weight=1)

		self._text.grid(row=0, column=0, sticky='nesw')
		self._yscroll.grid(row=0, column=1, sticky='ns')
		self._xscroll.grid(row=1, column=0, sticky='we')

	def get_data(self):
		data = self._text.get('1.0', 'end -1 chars') # strips the newline that Tk adds for some reason
		return data

	def reset(self):
		self._text.delete('1.0', 'end')

def to_rows(inp, rowsize):
	rem = 1 if (len(inp) % rowsize > 0) else 0
	for i in range(len(inp) // rowsize + rem):
		yield inp[(i * rowsize):((i + 1) * rowsize)]

def limit(src, size):
	limited = len(src) > size
	return src[:size], limited

def hexify(content, row_size=15):
	for row in to_rows(content, row_size):
		for c in row:
			h = hex(c)
			if len(h) < 4:
				h = h[:2] + '0' + h[2:]

			yield h + ' '

		if len(row) != row_size:
			spaces = (5 * ' ')  * (row_size - len(row))
			yield spaces

		for c in row:
			if c < 32 or c >= 127:
				yield '.'
			else:
				yield chr(c)

		yield '\n'

class BinaryFileView(ttk.Frame):

	MAX_FILE_SIZE = 1024 * 16

	def __init__(self, master):
		ttk.Frame.__init__(self, master, style='Fill.TFrame')
		self._data = None
		self._build()

	def _build(self):
		self.columnconfigure(0, weight=1)
		self.rowconfigure(1, weight=1)

		self._file = StringVar()
		self._name = ttk.Label(self, textvariable=self._file, style='Fill.TLabel', anchor='e')

		self._name.grid(row=0, column=0, sticky='nesw', ipadx=5, ipady=5)

		self._filebtn = ttk.Button(self, text='Select File', command=self.set_file)
		self._filebtn.grid(row=1, column=1, columnspan=2, sticky='nesw', padx=5, pady=5)

		self._filebtn.grid(row=0, column=1)

		self._preview_scrolly = ttk.Scrollbar(self)
		self._preview_scrollx = ttk.Scrollbar(self, orient='horizontal')
		self._preview = Text(self, state='disabled', wrap="none",
			yscrollcommand=self._preview_scrolly.set, xscrollcommand=self._preview_scrollx.set)
		self._preview_scrolly.configure(command=self._preview.yview)
		self._preview_scrollx.configure(command=self._preview.xview)

		self._preview_scrolly.grid(row=1, column=2, sticky='ns')
		self._preview_scrollx.grid(row=2, column=0, columnspan=2, sticky='we')
		self._preview.grid(row=1, column=0, columnspan=2, sticky='nesw')

	def set_file(self, *_):
		fn = filedialog.askopenfilename()
		if fn:
			self._file.set(fn)
			self.load_preview(fn)

	def load_preview(self, filename):
		with open(filename, 'rb') as fp:
			data = fp.read()
			prev, limited = limit(data, BinaryFileView.MAX_FILE_SIZE)

		self._data = data

		self._preview.configure(state='normal')
		self._preview.delete('1.0', 'end')

		for chunk in hexify(prev):
			self._preview.insert('insert', chunk)

		if limited:
			self._preview.insert('insert', '\n[preview limited]')

	def reset(self):
		self._data = None
		self._preview.delete('1.0', 'end')
		self._file.set('')

	def get_data(self):
		return self._data

class TkSafeContext:
	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, tb):
		if exc_type == TclError:
			return True
		elif exc_type is not None:
			return False
		else:
			pass

class Configuration:

	def __init__(self, filename):
		self._fn = filename
		try:
			with open(filename, 'r') as fp:
				self._config = json.load(fp)
		except FileNotFoundError:
			self._config = {}
		except IOError:
			self._config = {}
			warnings.warn("Could not access configuration file.")
		except json.decoder.JSONDecodeError:
			self._config = {}
			warnings.warn("Invalid config JSON, using blank config")

	def get(self, key, validate, default):
		if key not in self._config:
			return default
		else:
			val = self._config[key]
			if isinstance(validate, type):
				valid = isinstance(val, validate)
			elif callable(validate):
				valid = validate(val)
			else:
				raise TypeError("invalid validator - must be a type of a validation function")

			if valid:
				return val
			else:
				return default

	def save(self):
		if not os.path.isfile(self._fn):
			# create parent dirs
			try:
				os.makedirs(os.path.dirname(self._fn), exist_ok=True)
			except PermissionError:
				warnings.warn("Could not create parent directories to save configuration.")
				return

		try:
			with open(self._fn, 'w') as fp:
				json.dump(self._config, fp)
		except IOError:
			warnings.warn("Could not open config file for writing.")

	def __getitem__(self, val):
		return self._config[val]

	def __setitem__(self, key, val):
		self._config[key] = val

	def __contains__(self, key):
		return key in self._config

	def __str__(self):
		return str(self._config)

def valid_recent(rec):
	if isinstance(rec, dict):
		url = rec.get('url', None)
		try:
			WebSocket.parse_uri(url)
		except:
			return False

		headers = rec.get('headers', None)
		if isinstance(headers, dict):
			return all([re.match(HttpRequest.HEADER_RE, f'{key}: {value}') for (key, value) in headers.items()])
		else:
			return False

def valid_recents(rec):
	if isinstance(rec, list):
		return all([valid_recent(recent) for recent in rec])
	else:
		return False

class Sockman(ttk.Frame):

	DATA_TYPES = {
		'JSON': JsonView,
		'Plain Text': TextView,
		'Binary Data': BinaryFileView
	}

	TO_SERVER = '\u2191'
	TO_CLIENT = '\u2193'

	DATA_DIR = os.path.join('~', '.sockman') # expanded with os.path.expanduser, which works on Windows too
	CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')

	def __init__(self, master, context, quit=None, **kw):
		ttk.Frame.__init__(self, master, **kw)
		setup_style(master)
		self._master = master
		self._ctx = context

		self._disabled = True

		self._sock = None
		self._connecting = False
		self._messages = {}
		self._quit = quit

		self._load_config()
		self._build()

	def _load_config(self):
		full_path = os.path.expanduser(Sockman.CONFIG_FILE)
		self.config = Configuration(full_path)

	def _build(self):
		self._master.title("Sockman")
		self._master.bind("<Configure>", self._on_cfg)

		self.columnconfigure(0, weight=1)
		self.columnconfigure(1, weight=1)
		self.rowconfigure(0, weight=1)

		data_in = ttk.Frame(self)
		data_in.grid(row=0, column=0, sticky='nesw')

		data_in.columnconfigure(0, weight=1)
		data_in.rowconfigure(2, weight=1)

		self._views = {}
		for dtype in Sockman.DATA_TYPES.keys():
			view_con = Sockman.DATA_TYPES[dtype]
			if view_con is None:
				self._views[dtype] = None
			else:
				self._views[dtype] = view_con(data_in)

		self._in_view = None

		self._data_type = StringVar()
		opts = tuple(Sockman.DATA_TYPES.keys())
		self._data_type.set(opts[0])
		self._data_type.trace('w', self.set_view)
		options = ttk.OptionMenu(data_in, self._data_type, opts[0], *opts)
		options.grid(row=0, column=0, sticky='nesw')

		toolbar = ttk.Frame(data_in, style='Toolbar.TFrame')
		toolbar.grid(row=1, column=0, sticky='nesw')

		toolbar.columnconfigure(1, weight=1)

		self._reset = ttk.Button(toolbar, text="Reset", command=self.reset)
		self._reset.grid(row=0, column=0, padx=5, pady=5, sticky='nesw')

		self._send = ttk.Button(toolbar, text="Send", command=start(self.send))
		self._send.grid(row=0, column=2, padx=5, pady=5, sticky='nesw')

		out_view = ttk.Frame(self)
		out_view.grid(row=0, column=1, sticky='nesw')

		out_view.columnconfigure(0, weight=1)
		out_view.rowconfigure(0, weight=1)
		out_view.rowconfigure(1, weight=1)

		self._logs = ttk.Treeview(out_view)
		self._logs['columns'] = ('direction', 'preview', 'timestamp')

		self._logs.column('#0', width=0, stretch=False)
		self._logs.heading('#0', text='', anchor='center')

		self._logs.column('direction', width=75, stretch=False, anchor='center')
		self._logs.column('preview', stretch=True, anchor='w')
		self._logs.column('timestamp', width=100, stretch=False, anchor='center')

		self._logs.heading('direction', text='Direction', anchor='center')
		self._logs.heading('preview', text='Preview', anchor='center')
		self._logs.heading('timestamp', text='Timestamp', anchor='center')

		self._logs.grid(row=0, column=0, columnspan=2, sticky='nesw')
		self._logs.bind("<<TreeviewSelect>>", self._log_select)

		self._preview_scrolly = ttk.Scrollbar(out_view)
		self._preview_scrollx = ttk.Scrollbar(out_view, orient='horizontal')
		self._preview = Text(out_view, state='disabled', wrap="none",
			yscrollcommand=self._preview_scrolly.set, xscrollcommand=self._preview_scrollx.set)
		self._preview_scrolly.configure(command=self._preview.yview)
		self._preview_scrollx.configure(command=self._preview.xview)
		self._preview_scrolly.grid(row=1, column=1, sticky='ns')
		self._preview_scrollx.grid(row=2, column=0, sticky='we')
		self._preview.grid(row=1, column=0, sticky='nesw')

		self._status = StringVar()
		self._status.set("Started")
		self._status_lbl = ttk.Label(out_view, textvariable=self._status, style='Status.TLabel')
		self._status_lbl.grid(row=3, column=0, ipadx=5, ipady=5, columnspan=2, sticky='nesw')

		# menubar
		mb = Menu(self._master)

		file = Menu(mb, tearoff=0)
		file.add_command(label="Export Logs", command=self.export_logs)
		file.add_separator()
		file.add_command(label="Exit", command=self.quit)

		conn = self._conn = Menu(mb, tearoff=0)
		conn.add_command(label="Connect", command=self._connect)

		about = Menu(mb, tearoff=0)
		about.add_command(label="About Sockman", command=self._about)

		recents = self.config.get('recent', valid_recents, None)
		if recents is not None:
			recent = Menu(conn, tearoff=0)
			for rec in recents:
				try:
					WebSocket.parse_uri(rec['url'])
				except:
					# ignore invalid values
					continue

				heads = len(rec["headers"])
				recent.add_command(label=rec['url'] + f' (with {heads} header{"s" if heads != 1 else ""})', command=functools.partial(self._connect, rec))

			conn.add_cascade(label="Recent", menu=recent)

		conn.add_command(label="Close", command=self._close)
		self.can_close(False)

		self._verify = BooleanVar()
		self._verify.set(1)
		conn.add_checkbutton(label="Verify SSL", onvalue=1, offvalue=0, variable=self._verify)

		mb.add_cascade(label="File", menu=file)
		mb.add_cascade(label="Connection", menu=conn)
		mb.add_cascade(label="About", menu=about)

		self._master.config(menu=mb)

		self.disable()

	def can_close(self, val):
		if val:
			self._conn.entryconfig("Close", state="normal")
		else:
			self._conn.entryconfig("Close", state="disabled")

	def _about(self):
		dlg = AboutDialog(self._master)
		self.show_dialog(dlg)

	def _close(self):
		if self._sock is not None and self._sock.state == WebSocket.State.OPEN:
			self._sock.close()

	def _log_select(self, *_):
		self._preview.configure(state='normal')
		self._preview.delete('1.0', 'end')
		sel = self._logs.selection()
		if len(sel) == 0:
			return

		sel = sel[0]
		data = self._messages[sel]['data']
		limited = False
		if isinstance(data, str):
			try:
				data = json.dumps(json.loads(data), indent=2)
			except json.decoder.JSONDecodeError:
				pass
		else:
			data, limited = limit(data, BinaryFileView.MAX_FILE_SIZE)
			data = ''.join(hexify(data))
		self._preview.insert('insert', data)
		if limited:
			self._preview.insert('insert', '\n[preview limited]')
		self._preview.configure(state='disabled')

	def reset(self):
		if self._in_view is not None:
			if hasattr(self._in_view, 'reset'):
				self._in_view.reset()

	async def send(self):
		if self._in_view is not None:
			data = self._in_view.get_data()
			if data is None:
				return

			if not self._disabled:
				enable = True
				self.disable()
			else:
				enable = False

			# force change to reflect immediately
			self._master.update()

			dtype = WebSocket.TEXT_FRAME if isinstance(data, str) else WebSocket.BINARY_FRAME

			loop = asyncio.get_running_loop()
			cbk = None
			def safe_cbk(progress):
				if callable(cbk):
					cbk(progress)

			task = loop.create_task(self._sock.send(data, on_progress=safe_cbk))
			started = datetime.now()
			dlg = None

			# used to ignore TclErrors caused
			# by calls to tk functions after
			# root.destroy() is called, usually
			# by the "x" button being called.
			with TkSafeContext():
				while not task.done():
					if dlg is None:
						diff = (datetime.now() - started).total_seconds()
						if diff >= 0.1:
							dlg = ProgressDialog(self)
							dlg.wait_visibility()
							dlg.focus()
							dlg.grab_set()
							self._master.update()
							cbk = dlg.update_progress

					await asyncio.sleep(0.01)

				exc = task.exception()
				if exc is not None:
					raise exc

			if enable:
				self.enable()

			preview = Sockman.preview({
				'type': dtype,
				'text' if dtype == WebSocket.TEXT_FRAME else 'binary': data
			})
			self.log(data, preview=preview, direction=Sockman.TO_SERVER)

	def disable(self):
		self._disabled = True
		self._send.configure(state='disabled')

	def enable(self):
		self._disabled = False
		self._send.configure(state='normal')

	def onmessage(self, received):
		data = received.get('text', received.get('binary', None))
		self.log(data, preview=Sockman.preview(received), direction=Sockman.TO_CLIENT)

	def reset_all(self):
		self.reset() # resets inputs

		self._messages = {}
		self._logs.delete(*self._logs.get_children())
		for view in self._views.values():
			if hasattr(view, 'reset'):
				view.reset()

	def finish(self):
		# called when the application is exited

		# necessary to unlink all handlers that interact with the GUI
		# once the GUI has been destroyed
		if self._sock is not None:
			self._sock.unset_handler(self.onclose, handler_type='close')

		self.config.save()

	def onping(self):
		self.log('[sent ping]')

	def onclose(self, status):
		self.can_close(False)
		self._sock = None
		self.disable()
		self.status('Connection closed.')

		msg = '[connection closed]'
		self.log(msg + f'\n\nStatus: {status}', msg)

	def _connect(self, rec=None):
		if rec is None:
			if not self._connecting:
				self.disable()

				self._connecting = True
				dlg = ConnectDialog(self)
				self.show_dialog(dlg)
				self._connecting = False

				if not dlg.ok:
					return

				target = dlg.url.get()
				headers = dlg.get_headers()
			else:
				return
		else:
			target = rec['url']
			headers = rec['headers']

		if self._sock is not None:
			self._sock.close()
			self._sock = None
		try:
			WebSocket.parse_uri(target)
		except ValueError:
			self.error("Invalid WebSocket URI.")
			return

		try:
			self._sock = self._ctx.create_socket(target, WebSocketContext.DEFAULT_TIMEOUT,
				verify=bool(self._verify.get()), mode=WebSocket.Mode.EVENT, headers=headers)
			self._sock.handler(self.onmessage)
			self._sock.handler(self.onclose, handler_type='close')
			self._sock.handler(self.onping, handler_type='ping')
		except ValueError as ve:
			self._sock = None
			self.error(str(ve))
			return

		recents = self.config.get('recent', valid_recents, None)
		if recents is not None:
			data = {
				'url': target,
				'headers': headers
			}
			if data not in recents:
				self.config['recent'].insert(0, data)
				if len(self.config['recent']) > 5:
					self.config['recent'] = self.config['recent'][:5]
		else:
			self.config['recent'] = [{
				'url': target,
				'headers': headers
			}]

		self.can_close(True)
		self.enable()
		self.reset_all()
		self.success("Successfully connected to " + target)

		msg = '[connection opened]'
		if len(headers) > 0:
			post = '\n\nHeaders:\n' + HttpRequest.make_headers(headers, '\n')
		else:
			post = ''
		self.log(msg + post, msg)

	def log(self, data, preview=None, direction=''):
		if preview is None:
			preview = data

		uid = str(uuid.uuid4())
		timestamp = Sockman.timestamp()
		self._messages[uid] = {
			'data': data,
			'timestamp': time.time(),
			'direction': '[to server]' if direction == Sockman.TO_SERVER else ('[from server]' if direction == Sockman.TO_CLIENT else '')
		}
		self._logs.insert(parent='', index='end', text='', iid=uid, values=(direction, preview, timestamp))
		return uid

	def status(self, msg):
		self._status_lbl.configure(style='Status.TLabel')
		self._status.set(msg)

	def success(self, msg):
		self._status_lbl.configure(style='Success.Status.TLabel')
		self._status.set(msg)

	def error(self, msg):
		self._status_lbl.configure(style='Error.Status.TLabel')
		self._status.set(msg)

	def set_view(self, *_):
		if self._in_view is not None:
			self._in_view.grid_forget()

		view = self._data_type.get()
		view_inst = self._views[view]
		if view_inst is not None:
			self._in_view = view_inst
			view_inst.grid(row=2, column=0, sticky='nesw')

	def show_dialog(self, toplevel):
		def center(*_):
			pos = parse_geometry(self._master.geometry())[1]
			size = self._master.winfo_width(), self._master.winfo_height()
			tsize = toplevel.winfo_width(), toplevel.winfo_height()
			cx = int(((size[0] - tsize[0]) / 2))
			cy = int(((size[1] - tsize[1]) / 2))
			toplevel.geometry(f'+{cx}+{cy}')

		toplevel.bind("<Configure>", center)

		toplevel.transient(self._master)
		toplevel.grab_set()
		self._master.wait_window(toplevel)

	def _on_cfg(self, _):
		self.pack(expand=True, fill='both')

	def quit(self):
		if callable(self._quit):
			self._quit()

	def export_logs(self):
		outfile = filedialog.asksaveasfilename()
		if outfile:
			try:
				with open(outfile, 'w') as fp:
					self.write_logs(fp)
			except IOError:
				self.error("Could not write logs - unable to write to file.")

	def write_logs(self, fp):
		sort_map = sorted(self._messages.values(), key=lambda ent: ent['timestamp'])
		if len(sort_map) > 0:
			sort_map[0]['first'] = True

		for message in sort_map:
			data = message['data']
			if isinstance(data, bytes):
				data = base64.b64encode(data).decode('ascii')

			if not message.get('first', False):
				fp.write('\n')

			fp.write(f"{message['timestamp']} {message['direction']}: {data}")

	@staticmethod
	def timestamp():
		return datetime.now().strftime('%H:%M:%S')

	@staticmethod
	def preview(message):
		mtype = message['type']
		if mtype == WebSocket.TEXT_FRAME:
			prev, lim = limit(message['text'], 128)
			if lim:
				prev += '...'
			return prev
		elif mtype == WebSocket.BINARY_FRAME:
			return '[binary data (size %dB)]' % len(message['binary'])
		else:
			return '[unknown data]'