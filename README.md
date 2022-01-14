Sockman
-------

Sockman is a lightweight WebSocket testing suite. You can connect to a WebSocket server,
send and receive data, review sent/received data, and export the activity logs to a file.

Sockman was written using Python 3.9.7, but should be able to run on any version 3.5+ (owing
to its use of async/await and asyncio). It can run without installation of outside packages
from pip, but the requirements.txt file included can be used to run a simple local test server.

Running the Test Server
-----------------------

1. Create a virtual environment: `python3 -m venv .env`
2. Enter the virtual environment: `source .env/bin/activate`
3. Execute `pip install -r requirements.txt`
4. Run `uvicorn test:test_server`

Running Sockman
---------------

1. No need for a virtual environment or anything. Simple as `python3 .`

Acknowledgements
----------------

Credits to [RedFantom](https://github.com/RedFantom) for his ttk theme "arc", which can be found in the
ttkthemes repository [here](https://github.com/TkinterEP/ttkthemes/).