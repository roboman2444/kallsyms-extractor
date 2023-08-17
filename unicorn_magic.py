from unicorn import *
from unicorn.x86_const import *
from traceback import print_exc
from pprint import pprint

#from capstone import Cs, CS_ARCH_X86, CS_MODE_64

_INSTRUCTION_COUNTER = 0

#TODO have an actual PROPER way ot setting this (and testing that it actually works!)
#little bit of a hack
_my_own_sprinter_va = None
_my_own_sprinter_pa = None
_my_own_sprinter_dump = None

#TODO have this initial list settable by an arg?
bad_areas = set()
bad_area_names = ["cond_resched"]

def hook_mem_invalid(uc, access, address, size, value, user_data):
    global bad_areas
    rip = uc.reg_read(UC_X86_REG_RIP)
    if access == UC_MEM_WRITE_PROT or access == UC_MEM_WRITE_UNMAPPED:
        print("Mem_invalid_write insn 0x%x @ 0x%x" % (rip, address))
    elif access == UC_MEM_FETCH_PROT or access == UC_MEM_FETCH_UNMAPPED:
        print("Mem_invalid_fetch insn 0x%x @ 0x%x" % (rip, address))
    else:
        print("Mem_invalid_read insn 0x%x @ 0x%x" % (rip, address))

    #if we have access to sprinter, and this access was caused by a naughty function, we can add it to ze list
    if _my_own_sprinter_va:
        sp = sprint_symbol(_my_own_sprinter_dump, _my_own_sprinter_va, _my_own_sprinter_pa, rip)
        nm, symoffset, symsize = decode_sprint_res(sp)
        if any([ k in nm for k in bad_area_names ]):
            symstart = rip - symoffset
            bad_areas.add((symstart, symsize))
            print(f"bad function with a bad access {nm} from 0x{symstart:x} len 0x{symsize:x}")
            return False

    return True

def align_page(a):
    return a & ~0xfff

def read_str(uc, address):
    s = b""
    while b"\x00" not in s:
        s += uc.mem_read(address, 1)
        address+=1
    return s[:-1]

def hook_code64(uc, address, size, user_data):
    global _INSTRUCTION_COUNTER
    _INSTRUCTION_COUNTER += 1

    ksyms, callback_addr = user_data

    # So we executed more than 10**6 instructions and found less than 10 kallsyms? Probably not the correct function.
    if len(ksyms) < 10 and _INSTRUCTION_COUNTER > 10000000:
        uc.emu_stop()
        return

#    print(">>> Tracing instruction at 0x%x, callback at 0x%x %d" % (address, callback_addr, _INSTRUCTION_COUNTER))
#    if _my_own_sprinter_va:
#        sp = sprint_symbol(_my_own_sprinter_dump, _my_own_sprinter_va, _my_own_sprinter_pa, address)
#        print(sp)
#        nm, _, _ = decode_sprint_res(sp)
#        if "cond_resched" in nm:
#            uc.reg_write(UC_X86_REG_RAX, 0)
#            uc.reg_write(UC_X86_REG_RIP, callback_addr+1)
#    insn = uc.mem_read(address, size)
#    md = Cs(CS_ARCH_X86, CS_MODE_64)
#    for i in md.disasm(insn, address):
#        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


    if address == callback_addr:
        sym_name = read_str(uc, uc.reg_read(UC_X86_REG_RSI)).decode("utf-8")
        sym_address = int(uc.reg_read(UC_X86_REG_RCX))
        #print("FOUND: 0x%x %s" % (sym_address, sym_name))
        ksyms.append((sym_address, sym_name))
        uc.reg_write(UC_X86_REG_RAX, 0)


def decode_sprint_res(res):
	nme = None
	offset = None
	size = None
	try:
		plussplit = res.split("+")
		if len(plussplit) > 2:
			print("PLUSSPLIT WRONG!\n")
		nme = plussplit[0].strip()
		slashsplit = plussplit[1].split("/")
		if len(plussplit) > 2:
			print("SLASHSPLIT WRONG!\n")
		offset = int(slashsplit[0].strip(), 16)
		size = int(slashsplit[1].strip(), 16)
	except:
		pass
	return nme, offset, size

def sprint_symbol(dump, sprint_va, sprint_pa, addr):
    global _my_own_sprinter_va, _my_own_sprinter_pa, _my_own_sprinter_dump


    ksyms = []
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    #yes, it is supposed to be min(pa) on both...
    # We read 16mb before and 64mb after kallsyms_on_each_symbols, is should be enough to cover all the kernel .text and data.
    load_va = align_page(sprint_va - min(sprint_pa, 2**24))
    load_pa = align_page(sprint_pa - min(sprint_pa, 2**24))
    mem     = dump[load_pa:load_pa+2**26]

    mu.mem_map(load_va, len(mem))
    mu.mem_write(load_va, mem)

    # Map the zero page for gs:0x28 accesses
    mu.mem_map(0, 4096)
    mu.mem_write(0, b"\x00"*4096)

    # Setup the stack...
    STACK      = 0x200000
    STACK_SIZE = 0x100000
    mu.mem_map(STACK - STACK_SIZE, STACK)
    mu.reg_write(UC_X86_REG_RSP, STACK)
    try:
        mu.reg_write(UC_X86_REG_GS, 0x1000)
    except unicorn.UcError:
        pass

    buffer_addr = load_va
    mu.mem_write(buffer_addr, b"\x00")
    mu.reg_write(UC_X86_REG_RDI, buffer_addr)
    mu.reg_write(UC_X86_REG_RSI, addr)


    # Add hooks
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)

    # Go!
    try:
        mu.emu_start(sprint_va, sprint_va+0x20000)
    except (unicorn.UcError, KeyError):
#todo actually do a check
#        print_exc()
#        print("unicorn throw an exception, we should be done here..")
        pass
    result = read_str(mu, buffer_addr).decode("utf-8")
    _my_own_sprinter_va = sprint_va
    _my_own_sprinter_pa = sprint_pa
    _my_own_sprinter_dump = dump
    return result

def extract_symbols(dump, kallsyms_on_each_va, kallsyms_on_each_pa):
  global _INSTRUCTION_COUNTER
  global bad_areas
  bad_areas = set()
  bad_area_old_len = 0
  ksyms_accum = []
  while True:
    ksyms = []
    _INSTRUCTION_COUNTER = 0

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    #yes, it is supposed to be min(pa) on both...
    # We read 16mb before and 64mb after kallsyms_on_each_symbols, is should be enough to cover all the kernel .text and data.
    load_va = align_page(kallsyms_on_each_va - min(kallsyms_on_each_pa, 2**24))
    load_pa = align_page(kallsyms_on_each_pa - min(kallsyms_on_each_pa, 2**24))
    mem     = dump[load_pa:load_pa+2**26]

    mu.mem_map(load_va, len(mem))
    mu.mem_write(load_va, mem)

    # Map the zero page for gs:0x28 accesses
    mu.mem_map(0, 4096)
    mu.mem_write(0, b"\x00"*4096)
    # Map the zero page BIG (512k) for gs:0x28 and whacky GS accesses
#    mu.mem_map(0, 0x80000)
#    mu.mem_write(0, b"\x00"*0x80000)

    # Setup the stack...
    STACK      = 0x200000
    STACK_SIZE = 0x100000
    mu.mem_map(STACK - STACK_SIZE, STACK)
    mu.reg_write(UC_X86_REG_RSP, STACK)
    try:
        mu.reg_write(UC_X86_REG_GS, 0x1000)
    except unicorn.UcError:
        pass

    # Inject our fake callback function, which consists only of a ret
    callback_addr = load_va
    mu.mem_write(callback_addr, b"\xc3")
    mu.reg_write(UC_X86_REG_RDI, callback_addr)

    # Add hooks
    mu.hook_add(UC_HOOK_CODE, hook_code64, (ksyms, callback_addr))
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, callback_addr)


    # bad areas, just set em to rets
    for bstart, blen in bad_areas:
        mu.mem_write(bstart, b"\xc3"*blen)

    # Go!
    try:
        mu.emu_start(kallsyms_on_each_va, kallsyms_on_each_va+0x20000)
    except (unicorn.UcError, KeyError):
        print_exc()
        print("unicorn throw an exception, we should be done here..")
        pass

    ksyms_accum += ksyms
    if len(bad_areas) > bad_area_old_len:
        print("we found some bad areas that go around, so let's try again")
        bad_area_old_len = len(bad_areas)
        continue

    return ksyms_accum
