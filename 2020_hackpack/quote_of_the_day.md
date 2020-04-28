# Quote of the Day
  
**Category: re**  
**Value: 490**  
**Flag: flag{h3r3s_y3r_pr1z3_4_pl@y1ng}**  

## Description


BigCorp is considering changing vendors for their mission-critical quote-of-the-day servers.  Naturally, they are concerned that the new software be very secure.  The new vendor has set up a sample server at `cha.hackpack.club:41709` for BigCorp's security evaluation.

The server source code is a tightly guarded proprietary trade secret protected by lawyer-sharks with DMCA-lasers on their heads, but the client binary is freely available from the vendor.  Can you reverse it to find any backdoors in the vendor's server?  

## Files
  
- client

## Solution

After decompiling the client with Ghidra we can see some, relatively simple, methods besides main: send_all, send_mesage, read_message, check_message, do_quote, do_echo and **(one functionality that doesn't appear in the menu)** do_debug_test.

The logic was copied to a Python script to be able to work better with it (full script at the end).

### Format of the message used for communication:
* **CMD**: 4 bytes (uint32) representing the type of message/command
* **LEN**: 4 bytes (uint32) for the length of the text (if any)
* **MSG**: LEN bytes containing the text/payload

For each type of CMD there was a response code.

When calling the do_debug method (CMD=0x2a) you get an error response "badload" and a hint to try with "old.qotd" or "default.qotd". For any other CMD code, except QUOTE and ECHO, the response was "badkind".

When "old" or "default" is sent as MSG for the DEBUG command, the response was "cha-ching" :)

After calling the previous command, the quotes changed and after requesting 15 quotes you get the flag.
Although the quotes changed after calling the method with any of the messages, _only after using "old" you get the flag_.


````python
from pwn import *
context.update(arch='i386', os='linux')

HOST = 'cha.hackpack.club'
PORT = 41709

CMD_QUOTE = 0x14
CMD_QUOTE_RESPONSE = 0x15
CMD_DEBUG = 0x2a
CMD_DEBUG_RESPONSE = 0x2b
CMD_ECHO = 0xa
CMD_ECHO_RESPONSE = 0xb
CMD_BADKIND_RESPONSE = 0x5b

def htonl(n):
	return p32(n, endian='big')

def ntohl(n):
	return u32(n, endian='big')

class Client:
	def __init__(self, host, port):
		self.host = host
		self.port = port

	def start(self):
		self.connect()
		msg = self.check_message(1, 0x3ff)
#		print(f'server: {msg}')

	def connect(self):
		self.remote = remote(self.host, self.port)

	def do_debug(self, msg: bytes=b''):
		self.send_message(CMD_DEBUG, msg)
		msg, msg_ok = self.read_message(0xff)
		if msg_ok < 0:
			raise Exception('Error debug testing')
		print(f'debug({msg_ok}): {msg.decode()}')

	def do_debug_old(self):
		self.do_debug(b'old')

	def do_debug_default(self):
		self.do_debug(b'default')

	def do_quote(self, msg: bytes=b''):
		self.send_message(CMD_QUOTE, msg)
		msg = self.check_message(CMD_QUOTE_RESPONSE, 0xff)
		print(f'quote: {msg.decode()}')

	def do_echo(self, msg_in: bytes):
		self.send_message(CMD_ECHO, msg_in)
		msg_out = self.check_message(CMD_ECHO_RESPONSE, 0xff)
		print(f'echo: {msg_out.decode()}')

	def check_message(self, msg_expected, msg_max_len):
		msg, msg_ok = self.read_message(msg_max_len)
		if msg_ok == msg_expected:
			return msg
		raise Exception('Error checking message')

	def read_message(self, msg_max_len):
		header = self.remote.recv(8)
		msg_ok = ntohl(header[:4])
		msg_len = ntohl(header[4:])
		recv_len = msg_max_len
		if msg_len < msg_max_len:
			recv_len = msg_len
		msg = self.remote.recv(recv_len)
		#print(f'max_len: {msg_max_len} msg_ok: {msg_ok} msg_len: {msg_len} header: {header} msg: {msg}')
		if len(msg) == recv_len:
			return msg, msg_ok
		raise Exception('Error receiving message')

	def send_message(self, cmd: int, data: bytes):
		self.send_all(htonl(cmd)+htonl(len(data)))
		if len(data) > 0:
			self.send_all(data)

	def send_all(self, data):
		self.remote.send(data)


c = Client(HOST, PORT)
c.start()
c.do_debug_default()
for i in range(20):
	c.do_quote()
c.do_debug_old()
for i in range(20):
	c.do_quote()
  ````
  
***Vox Dei***

