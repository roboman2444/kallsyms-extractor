#!/usr/bin/env python3

if __package__:
    from .unicorn_magic import extract_symbols
    from .unicorn_magic import sprint_symbol, decode_sprint_res
else:
    from unicorn_magic import extract_symbols
    from unicorn_magic import sprint_symbol, decode_sprint_res

import argparse
import pathlib
import tempfile
import struct
import mmap
import sys
import re
import os
from pprint import pprint
from traceback import print_exc
import json


#TODO re-implement finding phys_base using the original ref trickery
#TODO implement a sprint-only method. (sprint entire thing)



#todo make this an arg
THRESHOLD_KALLSYMS = 100
THRESHOLD_KSYMTAB  = 100

#TODO make this an arg. Make this settable to a size
QUICKSEARCH = True
#todo arg. Searches non-aligned
REF_SEARCH_OFFSETS = False


PHYS_BASE = 0x0

def read_str(dump, address):
    end  = dump[address:address+1024].index(b'\x00')
    try:
        return dump[address:address+end].decode('utf-8')
    except UnicodeError:
        return ""


def find_kaslr_base_fix(symbol_dict):
	_text_base = 0xffffffff81000000
	# find _text
#	pprint(ksyms)
	for testsym in ["_text", "_stext", "startup_64"]:
		addr = symbol_dict.get(testsym)
		if addr:
			#redundant check.....
			if isinstance(addr, set): #TODO look into handling more than one
				#for now i'll just choose the lowest
				last = list(addr)
				last.sort()
				addr = last[0]
			res = _text_base - addr
			print(f"Found {testsym} at 0x{addr:x}, kaslr base fix must be 0x{res:}")
			return res
	return None


def process_kaslr_base_fix(symbol_dict, fix_off):
	new_dict = {}
	for k,v in symbol_dict.items():
		new_set = set()
		for item in v:
			if item + fix_off > 0:
				item += fix_off
			new_set.add(item)
		new_dict[k] = new_set
	return new_dict

# Value can also be a per_cpu pointer, thus the check if is less than 0x100000
def is_valid_entry(value, name):
    return (name >= 0xffffffff80000000) and (0xffffffff80000000 <= value < 0xffffffffffffffff or value <= 0x100000)


#valid name is ascii, in dump post base, etc
#TODO look up what the allowed characters in linux kernel symbol names are
#TODO verify that it is in the right section
#TODO verify that it is aligned?
#TODO verify maximum length?
from string import ascii_lowercase, ascii_uppercase
valid_ksymbol_start_chars = ascii_lowercase + ascii_uppercase + '_'
def is_valid_name(dump, nameaddr):
	try:
		str = read_str(dump, nameaddr)
	except:
		print_exc()
		return False
	if len(str) < 1: return False
#	print(str)
	if str[0] not in valid_ksymbol_start_chars: return False

	return True

def extrapolate_candidate_ksymtab(dump, cand_loc, namespace = False, relref = False):
	low_ksym = cand_loc
	high_ksym = cand_loc

	ksymtab = []
	if namespace:
		ksymbol_fmt  = "<lll" if relref else "<QQQ"
	else:
		ksymbol_fmt  = "<ll" if relref else "<QQ"

	ksymbol_size = struct.calcsize(ksymbol_fmt)


#TODO dedup this, maybe sort it
#	print(f"\n[~] Extrapolating backward from 0x{cand_loc:x}")
	#move backwards, skip the first
	for i in range(cand_loc, 0, ksymbol_size):
		try:
			val,name = ksymbol_rel_extract(dump, i) if relref else ksymbol_dir_extract(dump, i)
		except struct.error:
			print_exc()
			break #TODO end of it?
		#verify that this is a symbol
		if not is_valid_name(dump, name):
			break
		low_ksym = i
		ksymtab.append((val, name))


	#not actually important since we sorteverything later anyway
	#flippy so we are the correct way around
	#ksymtab.reverse()

#	print(f"\n[~] Verifying 0x{cand_loc:x} is a relref candidate")
#	print(f"\n[~] Extrapolating forward from 0x{cand_loc:x}")
	#move forwards
	for i in range(cand_loc, dump.size(), ksymbol_size):
		try:
			val,name = ksymbol_rel_extract(dump, i) if relref else ksymbol_dir_extract(dump, i)
		except struct.error:
			print_exc()
			break #TODO end of it?
		#verify that this is a symbol
		if not is_valid_name(dump, name):
			break
		high_ksym = i
		ksymtab.append((val, name))

	return ksymtab, low_ksym, high_ksym




def find_string(dump, s):
    for match in re.finditer(s, dump):
        yield match.start()

def find_string_stock(dump, s):
	indx = 0
	while True:
		res = dump.find(s, indx)
		if res < 0:
			break
		indx = res+1
		yield res
def find_ref(dump, ref):
	sref = ref.to_bytes(8, 'little')
	yield from find_string_stock(dump, sref)


#addr in phys
def find_relref(dump, addr, offset=0, quicksearch=None):
	ref_fmt  = "<l"
	ref_size = struct.calcsize(ref_fmt) #todo verify if this works
	#ref_size = 4
	#todo limit this to +- int around addr, even without quicksearch. Just possible max-distances. (images may be bigger than 4gigs)

	print("\n[~] Finding candidate relref ksymtab (offset: %d, addr: %s, quicksearch %s)" % (offset, f"0x{addr:x}", f"0x{quicksearch:x}" if quicksearch else "Disabled"))

	startpoint = offset
	if quicksearch:
		startpoint += (quicksearch & ~0xfff) - 2**24 #16m before
	endpoint = dump.size()
	if quicksearch:
		endpoint = (quicksearch & ~0xfff) + 2**24 #16m after
	if endpoint > dump.size(): endpoint = dump.size()
	elif endpoint < 0: endpoint = 0
	if startpoint > dump.size(): startpoint = dump.size()
	elif startpoint < 0: startpoint = 0

	for i in range(startpoint, endpoint, ref_size):
		if i % 1000000 == offset:
			sys.stderr.write('\rDone %.2f%%' % ((i-startpoint)/(endpoint-startpoint)*100))
		try:
			ref     = dump[i:i+ref_size]
			value = struct.unpack(ref_fmt, ref)[0]
			fullrelptr = i + value
			if fullrelptr == addr:
				yield i
				print("goteeeeem\n")
		except struct.error:
			continue

#addr in phys
#TODO merge into find_relref? Just make one functiom? Most of this code is dup
def find_dirref(dump, addr, offset=0, quicksearch=None):
	ref_fmt  = "<Q"
	ref_size = struct.calcsize(ref_fmt) #todo verify if this works

	virt_addr = phy_to_virt(addr)

	#ref_size = 8
	#todo limit this to +- int around addr, even without quicksearch. Just possible max-distances. (images may be bigger than 4gigs)

	print("\n[~] Finding candidate directref ksymtab (offset: %d, addr: %s, quicksearch %s)" % (offset, f"0x{addr:x}", f"0x{quicksearch:x}" if quicksearch else "Disabled"))

	startpoint = offset
	if quicksearch:
		startpoint += (quicksearch & ~0xfff) - 2**24 #16m before
	endpoint = dump.size()
	if quicksearch:
		endpoint = (quicksearch & ~0xfff) + 2**24 #16m after
	if endpoint > dump.size(): endpoint = dump.size()
	elif endpoint < 0: endpoint = 0
	if startpoint > dump.size(): startpoint = dump.size()
	elif startpoint < 0: startpoint = 0

	for i in range(startpoint, endpoint, ref_size):
		if i % 1000000 == offset:
			sys.stderr.write('\rDone %.2f%%' % ((i-startpoint)/(endpoint-startpoint)*100))
		try:
			ref     = dump[i:i+ref_size]
			value = struct.unpack(ref_fmt, ref)[0]
			if value == virt_addr:
				yield i
				print("goteeeeem\n")
		except struct.error:
			continue

#returns phys addr
def ksymbol_rel_extract(dump, addr):
	ksymbol_rel_fmt = "<ll"
	ksymbol_rel_size = struct.calcsize(ksymbol_rel_fmt)
	ksymbol = dump[addr:addr+ksymbol_rel_size]
	valuerel, namerel = struct.unpack(ksymbol_rel_fmt, ksymbol)[:2]
	fullvalueptr = addr + valuerel
	fullnameptr = addr + 4 + namerel

	return fullvalueptr, fullnameptr


#returns virtual addr
def ksymbol_dir_extract(dump, addr):
	ksymbol_dir_fmt = "<QQ"
	ksymbol_dir_size = struct.calcsize(ksymbol_dir_fmt)
	ksymbol = dump[addr:addr+ksymbol_dir_size]
	value, name = struct.unpack(ksymbol_dir_fmt, ksymbol)[:2]

	return value, name



def phy_to_virt(phy):
	virt = phy + 0xffffffff80000000 - PHYS_BASE
	return virt
def virt_to_phy(virt):
	phy = virt - 0xffffffff80000000 + PHYS_BASE
	return phy

def find_phys_base(dump):
	global PHYS_BASE
	sstring = b"NUMBER(phys_base)="
	print(f"lookin for \"{sstring.decode('UTF-8')}\"")
	phys_pas = list(find_string_stock(dump, sstring))
	for phys_pa in phys_pas:
		try:
			dat_start = phys_pa + len(sstring)
			dat_end_null = dump.find(b"\x00", dat_start)
			dat_end_cr = dump.find(b"\r", dat_start)
			dat_end_nl = dump.find(b"\n", dat_start)
			dat_end = dat_start + 0x100
			if dat_end_null > dat_start and dat_end_null < dat_end: dat_end = dat_end_null
			if dat_end_cr > dat_start and dat_end_cr < dat_end: dat_end = dat_end_cr
			if dat_end_nl > dat_start and dat_end_nl < dat_end: dat_end = dat_end_nl
			dat = dump[dat_start:dat_end].decode("UTF-8")
			phys_base_candidate = int(dat)
			print(f"phys_base_candidate 0x{phys_base_candidate:x}")
			#TODO SEPERATE TESTS ON ALL?
			#TODO STORE AS LIST/SET?
			PHYS_BASE = phys_base_candidate
		except:
			print_exc()
	#hacky BS that should to be changed
	if PHYS_BASE != 0x0:
		return True
	return False



#yields relref ksymtab entry for the name
#physical addr of the ksymtab entry, vaddr of result, paddr of result
def find_symbol_ksymtabs(dump, sym_name, relref = False):
    name_pas = list(find_string(dump, sym_name))
    if len(name_pas) == 0:
        print("[-] " + str(sym_name) + " string not found, aborting!")
        sys.exit(-1)

    #relref
    for name_pa in name_pas:
        print("[+] Candidate " + str(sym_name) + " string found @ 0x%x" % name_pa)
        print(f"\tphy 0x{name_pa:x} -> virt 0x{phy_to_virt(name_pa):x}")
        if relref:
            print("\tLooking for relrefs...")
            ref_list = list(find_relref(dump, name_pa, quicksearch = name_pa if QUICKSEARCH else None))
        else:
            print("\tLooking for dirrefs...")
            ref_list = list(find_dirref(dump, name_pa, quicksearch = name_pa if QUICKSEARCH else None))

        print("")
        if REF_SEARCH_OFFSETS:
            if relref:
                for offi in range(1, 4):
                    ref_list += list(find_relref(dump, name_pa, offset=offi, quicksearch = name_pa if QUICKSEARCH else None))
                    print("")
            else:
                for offi in range(1, 8):
                    ref_list += list(find_dirref(dump, name_pa, offset=offi, quicksearch = name_pa if QUICKSEARCH else None))
                    print("")
        for ref_pa in ref_list:
            print("\t[+] Name ref found @ 0x%x" % ref_pa)
            print(f"\t\tphy 0x{ref_pa:x} -> virt 0x{phy_to_virt(ref_pa):x}")
            if relref:
                tab_start = ref_pa-4
                value_pa, fname_pa = ksymbol_rel_extract(dump, tab_start)
                value_va = phy_to_virt(value_pa)
                fname_va = phy_to_virt(fname_pa)
                print("[+] Candidate RELREF " + str(sym_name) + " function va: 0x%x pa: 0x%x name: 0x%x" % (value_va, value_pa, fname_va))
            else:
                tab_start = ref_pa-8
                value_va, fname_va = ksymbol_dir_extract(dump, tab_start)
                value_pa = virt_to_phy(value_va)
                fname_pa = virt_to_phy(fname_va)
                print("[+] Candidate DIRREF " + str(sym_name) + " function va: 0x%x pa: 0x%x name: 0x%x" % (value_va, value_pa, fname_va))

            yield tab_start, value_va, value_pa



#takes a list of (phyvalue, phyname)
#converts it to a of virtvalue string (if applicable) and yields
#also discards any names that wont work
def format_phy_table(table_full_phy):
	for phyval, phyname in table_full_phy:
		if not is_valid_name(dump, phyname): continue
		realname = read_str(dump, phyname)
		virtval = phy_to_virt(phyval)
		if virtval < 0x0: virtval = phyval #some entries are phyvals anyway....
		yield virtval, realname


#takes a (valid) phyical relref ksymtab entry, expands it, formats the table, saves it
def process_table_entry(dump, entry, relref = False):
	table_full_phy, le, he = extrapolate_candidate_ksymtab(dump, entry, relref = relref)
	table_full_phy2, le2, he2 = extrapolate_candidate_ksymtab(dump, entry, relref = relref, namespace = True)
	table_full_phy += table_full_phy2
	if le2 < le: le = le2
	if he2 > he: he = he2
	le_virt = phy_to_virt(le)
	table_full_format = list(format_phy_table(table_full_phy))
#	print(f"Ksymtab length: {len(table_full_format)}")
	save_relref_table_entries(table_full_format, le_virt, le)


#TODO track stuff like phys, virt, kaslr_fix, where i found it, etc
final_symbols ={}
def save_symbol(symname, addr):
	global final_symbols
	if not addr:
		print("NONE ADDR! " + symname)
		return
	#duplicate?
	out_addr = final_symbols.get(symname)
	if not out_addr:
		out_addr = set()
	out_addr.add(addr)

	final_symbols[symname] = out_addr

def write_final_save(out_file, symbol_dict):
	ksym_final_list = []
	for k, v in symbol_dict.items():
		if isinstance(v, set):
			for sv in v:
				if sv and k: ksym_final_list.append((sv, k))
		else: #redundant
			if v and k: ksym_final_list.append((v, k))

	#time to sort the thing
	ksym_final_list.sort(key=lambda x: x[0], reverse=False)
	with open(out_file, "w") as f:
		for value, name in ksym_final_list:
			f.write("%016x %s\n" % (value, name))
def write_final_json(out_json, symbol_dict):
	json_safe_dict = {}
	for k, v in symbol_dict.items():
		if isinstance(v, set):
			v = list(v)
			v.sort()
		json_safe_dict[k] = v
	with open(out_json, 'w') as f:
		json.dump(json_safe_dict, f, indent='\t')


def save_relref_table_entries(table_formatted, table_virt, table_phy):
	print(f"Table of length {len(table_formatted)} found at phy 0x{table_phy:x} -> virt 0x{table_virt:x}")
	for entry_val, entry_name in table_formatted:
		save_symbol(entry_name, entry_val)
#		print(f"0x{entry_val:016x} {entry_name}")


def save_kallsyms_on_each_result(ksyms, va, pa):
	print(f"kallsyms_on_each_function found at phy 0x{pa:x} -> virt 0x{va:x} produced this result")
	for entry_val, entry_name in ksyms:
		save_symbol(entry_name, entry_val)
#		print(f"0x{entry_val:016x} {entry_name}")


#general idea here
#start with sprint_symbol's own addr... this will get us pretty close.
# then walk, using the results of each sprint_symbol call to increment
#TODO error handle, handle not finding it, etc
def sprint_find_symbol(dump, va, pa, symbol):
	start_looky = va
	forward_looky = start_looky
	backward_looky = start_looky-0x4
	while True:
		if (forward_looky - start_looky) < (start_looky - backward_looky):
			sres = sprint_symbol(dump, va, pa, forward_looky)
			print("sprint symbol returned: " + sres)
			name, offset, size = decode_sprint_res(sres)
			print(f"forward sprinted parsed: name: {name}, offset: 0x{offset:x}, size: 0x{size:x}")
			addr = forward_looky - offset
			forward_looky += (size - offset)
		else:
			sres = sprint_symbol(dump, va, pa, backward_looky)
			print("sprint symbol returned: " + sres)
			name, offset, size = decode_sprint_res(sres)
			print(f"backward sprinted parsed: name: {name}, offset: 0x{offset:x}, size: 0x{size:x}")
			addr = backward_looky - offset
			backward_looky -= (offset + 0x4)
		if symbol == name:
			return addr, size



if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--force-sprint", action="store_true", help="force finding and emulating the sprint_symbol function.")
	parser.add_argument("--save-ksymtabs", action="store_true", help="Save symbols found in ksymtabs. (not kallsyms).")
	parser.add_argument("--extra-ksymtab", nargs="*", help="Extra symbols to search for. Specifiy more than once. An example is is --extra-ksymtab sprint_symbol --extra-ksymtab netdev_emerg")
	parser.add_argument("--kaslr-fix", action="store_true", help="apply a kaslr fix to the resulting symbols.")
	parser.add_argument("input", type=pathlib.Path, help="Dump in raw format.")
	parser.add_argument("--json", type=pathlib.Path, help="Output in Json.")
#TODO	parser.add_argument("--phys_base", help="Manually specify phys_base")
	parser.add_argument("--txt", type=pathlib.Path, help="Output in kallsyms text.")
	args = parser.parse_args()

	with open(args.input) as f:
		dump = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

	ATTEMPT_RELREF = True
	ATTEMPT_DIRREF = True
	JSON_SAVE = args.json
	TXT_SAVE=args.txt
	FORCE_HIGHEND_METHOD = args.force_sprint
	SAVE_KSYMTABS = args.save_ksymtabs
	KASLR_BASE_FIX = args.kaslr_fix


	EXTRA_KSYMTABS = []
	if args.extra_ksymtab:
		for k in args.extra_ksymtab:
			k = k.strip()
			bin = k.encode("utf-8") + b"/x00"
			EXTRA_KSYMTABS.append(bin)
	pprint(EXTRA_KSYMTABS)
	#todo able to manually specify phys_base
	if not find_phys_base(dump):
		print("unable to find phys base... dirref (currently) and relref wont work?")
		print("maybe you have to use --phys-base to manually specify one TODO")
		ATTEMPT_RELREF = False
		ATTEMPT_DIRREF = False

	relmodes = []
	if ATTEMPT_RELREF: relmodes.append(True)
	if ATTEMPT_DIRREF: relmodes.append(False)

	for relmode in relmodes:
		print("Attempting mode " + ("RELREF" if relmode else "DIRREF"))
	#relref attempts
		kall_res_len = 0
		possible_kallsyms = list(find_symbol_ksymtabs(dump, b"kallsyms_on_each_symbol\x00", relref = relmode))
#		possible_kallsyms = []
		for table_entry, va, pa in possible_kallsyms:
			# add that relref entry for processing
			if SAVE_KSYMTABS:
				process_table_entry(dump, table_entry, relref = relmode)
			ksyms = extract_symbols(dump, va, pa)
			print(f"Kallsyms length: {len(ksyms)}")
			kall_res_len += len(ksyms)

			save_kallsyms_on_each_result(ksyms, va, pa)

		if kall_res_len < THRESHOLD_KALLSYMS or FORCE_HIGHEND_METHOD:
			#we have to attempt the crazy method
			possible_sprint = list(find_symbol_ksymtabs(dump, b"sprint_symbol\x00", relref = relmode))
			for table_entry, va, pa in possible_sprint:
				# add that relref entry for processing
				if SAVE_KSYMTABS:
					process_table_entry(dump, table_entry, relref = relmode)

				# sprint for kallsyms_on_each_symbol
				found_kall_addr, size = sprint_find_symbol(dump, va, pa, "kallsyms_on_each_symbol")
				print(f"Sprint found kallsyms addr at 0x{found_kall_addr:x}")
				ksyms = extract_symbols(dump, found_kall_addr, virt_to_phy(found_kall_addr))
				print(f"Kallsyms length: {len(ksyms)}")
				save_kallsyms_on_each_result(ksyms, found_kall_addr, virt_to_phy(found_kall_addr))

		for symname in EXTRA_KSYMTABS:
			possible_sym_entry = list(find_symbol_ksymtabs(dump, symname, relref = relmode))
			for table_entry, va, pa in possible_sym_entry:
				# add that relref entry for processing
				process_table_entry(dump, table_entry, relref = relmode)



	if KASLR_BASE_FIX:
		kaslr_base_fix_off = find_kaslr_base_fix(final_symbols)
		if kaslr_base_fix_off:
			print(f"Found kaslr_base_fix_off 0x{kaslr_base_fix_off:x}")
			final_symbols = process_kaslr_base_fix(final_symbols, kaslr_base_fix_off)

	#pprint(final_symbols)
	if TXT_SAVE:
		write_final_save(TXT_SAVE, final_symbols)
		print("\n[+] KALLSYMS txt saved to: %s" % TXT_SAVE)
	if JSON_SAVE:
		write_final_json(JSON_SAVE, final_symbols)
		print("\n[+] JSON saved to: %s" % JSON_SAVE)
	exit(0)


