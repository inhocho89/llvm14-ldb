#-------------------------------------------------------------------------------
# elftools example: dwarf_decode_address.py
#
# Decode an address in an ELF file to find out which function it belongs to
# and from which filename/line it comes in the original source file.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
import sys
import csv
import copy
import math
import os

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

LDB_DATA_FILENAME = "ldb.data"

def parse_elf(executable):
    if not os.path.exists(executable):
        print('  Cannot find executable: {}'.format(executable))
        return None

    with open(executable, 'rb') as e:
        # get elf and dwarf information
        elffile = ELFFile(e)

        if not elffile.has_dwarf_info():
            print('  file has no debugging information')
            return None

        dwarfinfo = elffile.get_dwarf_info()

        return dwarfinfo

def parse_maps():
    if not os.path.exists("maps.data"):
        return None

    maps_arr = []
    with open("maps.data", 'r') as maps_file:
        csv_reader = csv.reader(maps_file, skipinitialspace=True, delimiter=' ')
        for row in csv_reader:
            if len(row) < 6:
                continue
    
            ranges = row[0].split('-')
            rg_start = int(ranges[0], 16)
            rg_finish = int(ranges[1], 16)
            #perms = row[1]
            offset = int(row[2], 16)
            #dev = row[3]
            #inode = row[4]
            pathname = ' '.join(row[5:])

            maps_arr.append({'start': rg_start,
                             'finish': rg_finish,
                             'offset': offset,
                             'pathname': pathname})

    return maps_arr

def decode_funcname(dwarfinfo, address):
    # Go over all DIEs in the DWARF information, looking for a subprogram
    # entry with an address range that includes the given address. Note that
    # this simplifies things by disregarding subprograms that may have
    # split address ranges.
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    lowpc = DIE.attributes['DW_AT_low_pc'].value

                    # DWARF v4 in section 2.17 describes how to interpret the
                    # DW_AT_high_pc attribute based on the class of its form.
                    # For class 'address' it's taken as an absolute address
                    # (similarly to DW_AT_low_pc); for class 'constant', it's
                    # an offset from DW_AT_low_pc.
                    highpc_attr = DIE.attributes['DW_AT_high_pc']
                    highpc_attr_class = describe_form_class(highpc_attr.form)
                    if highpc_attr_class == 'address':
                        highpc = highpc_attr.value
                    elif highpc_attr_class == 'constant':
                        highpc = lowpc + highpc_attr.value
                    else:
                        print('Error: invalid DW_AT_high_pc class:',
                              highpc_attr_class)
                        continue

                    if lowpc <= address < highpc:
                        return DIE.attributes['DW_AT_name'].value
            except KeyError:
                continue
    return None

def decode_file_line(dwarfinfo, addresses):
    ret = {}
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        offset = 1
        if len(lineprog['file_entry']) > 1 and \
                lineprog['file_entry'][0] == lineprog['file_entry'][1]:
            offset = 0
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate:
                addrs = [x for x in addresses if prevstate.address <= x < entry.state.address]
                for addr in addrs:
                    ret[addr] = {'fname': lineprog['file_entry'][prevstate.file - offset].name,
                            'line': prevstate.line,
                            'col': prevstate.column}
                    addresses.remove(addr)

                if len(addresses) == 0:
                    return ret
            if entry.state.end_sequence:
                # For the state with `end_sequence`, `address` means the address
                # of the first byte after the target machine instruction
                # sequence and other information is meaningless. We clear
                # prevstate so that it's not used in the next iteration. Address
                # info is used in the above comparison to see if we need to use
                # the line information for the prevstate.
                prevstate = None
            else:
                prevstate = entry.state
    return ret

def decode_dynamic(mapsinfo, addresses):
    ret = {}
    if len(addresses) == 0:
        return ret
    for mi in mapsinfo:
        addrs = [x for x in addresses if mi['start'] <= x < mi['finish']]
        for addr in addrs:
            ret[addr] = {'fname': mi['pathname'],
                    'offset': mi['offset'] + (addr - mi['start'])}
            addresses.remove(addr)

        if len(addresses) == 0:
            break

    return ret

def get_finfos(dwarfinfo, mapsinfo, addresses):
    # remove duplicates
    addresses = list(set(addresses))
    addresses.sort()

    finfomap = {}
    # initialize finfomap
    for addr in addresses:
        finfomap[addr] = "???"

    # nothing I can do without dwarfinfo
    if dwarfinfo == None:
        return finfomap

    # decode static addresses
    ret = decode_file_line(dwarfinfo, addresses)

    for key in ret:
        finfomap[key] = "{}:{:d}:{:d}"\
                .format(bytes2str(ret[key]['fname']), ret[key]['line'], ret[key]['col'])

    # decode dynamic addresses
    ret = decode_dynamic(mapsinfo, addresses)

    for key in ret:
        finfomap[key] = "{}+{}".format(ret[key]['fname'], hex(ret[key]['offset']))

    return finfomap

def generate_stats(executable):
    print('executable: {}'.format(executable))
    print('LDB data: {}'.format(LDB_DATA_FILENAME))

    latencies = {}
    dwarfinfo = parse_elf(executable)
    mapsinfo = parse_maps()
    nline = 0

    # collect latency informations
    with open(LDB_DATA_FILENAME, 'rb') as ldb_bin:
        while (byte := ldb_bin.read(40)):
            event_type = int.from_bytes(byte[0:4], "little")
            #ts_sec = int.from_bytes(byte[4:8], "little")
            #ts_nsec = int.from_bytes(byte[8:12], "little")
            #timestamp_us = ts_sec * 1000000 + ts_nsec / 1000.0
            #tid = int.from_bytes(byte[12:16], "little")
            latency = int.from_bytes(byte[16:24], "little") / 1000.0
            pc = int.from_bytes(byte[24:32], "little")
            #ngen = int.from_bytes(byte[32:40], "little")

            if event_type != 1:
                continue

            if pc in latencies:
                latencies[pc].append(latency)
            else:
                latencies[pc] = [latency]

    latencies_ordered = []
    pcs = []
    for pc, larr in latencies.items():
        pc -= 5
        larr.sort()
        N = len(larr)
        if larr[N-1] == 0.0:
            continue
        latencies_ordered.append({'pc': pc, 'num_samples': N, 'min': larr[0],
            'median': larr[int((N-1) * 0.5)], '90p': larr[int((N-1) * 0.9)],
            '99p': larr[int((N-1) * 0.99)], '999p': larr[int((N-1) * 0.999)],
            'max': larr[N-1]})
        pcs.append(pc)

    def dist_distance(e):
        return e['999p']
#        return e['999p'] - e['median']

    latencies_ordered.sort(key=dist_distance, reverse=True)

    finfomap = get_finfos(dwarfinfo, mapsinfo, pcs)

    for e in latencies_ordered:
        print('{} (pc={})'.format(finfomap[e['pc']], hex(e['pc'])))
        print('    num_samples: {:d}'.format(e['num_samples']))
        print('    min: {:.4f}'.format(e['min']))
        print('    median: {:.4f}'.format(e['median']))
        print('    90p: {:.4f}'.format(e['90p']))
        print('    99p: {:.4f}'.format(e['99p']))
        print('    99.9p: {:.4f}'.format(e['999p']))
        print('    max: {:.4f}'.format(e['max']))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected usage: {0} <executable>'.format(sys.argv[0]))
        sys.exit(1)
    generate_stats(sys.argv[1])
