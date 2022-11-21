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
MAPS_DATA_FILENAME = "maps.data"
PERF_DATA_FILENAME = "perf.data"
PERF_DEC_FILENAME = "perf.dec"

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


def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                col = prevstate.column
                return filename, line, col
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
    return None, 0, 0

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
    if not os.path.exists(MAPS_DATA_FILENAME):
        return None

    maps_arr = []
    with open(MAPS_DATA_FILENAME, 'r') as maps_file:
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

def decode_dynamic(mapsinfo, address):
    for mi in mapsinfo:
        if address >= mi['start'] and address < mi['finish']:
            return mi['pathname'], mi['offset'] + (address - mi['start'])

    return None, 0

def get_finfo(dwarfinfo, mapsinfo, address):
    if dwarfinfo == None:
        return "???"

    fname, line, col = decode_file_line(dwarfinfo, address)

    if fname != None:
        return "{}:{:d}:{:d}".format(bytes2str(fname), line, col)

    if mapsinfo == None:
        return "???"

    fname, offset = decode_dynamic(mapsinfo, address)

    if fname != None:
        return "{}+{}".format(fname, hex(offset))

    return "???"

def parse_ldb(executable, mreq):
    print('LDB Data: {}'.format(LDB_DATA_FILENAME))
    dwarfinfo = parse_elf(executable)
    mapsinfo = parse_maps()

    filter_req = []
    thread_list = []
    thread_context = []
    finfo_cache = {}
    nthread = 0
    min_tsc = 0
    max_tsc = 0

    # collect latency informations
    with open(LDB_DATA_FILENAME, 'rb') as ldb_bin:
        while (byte := ldb_bin.read(40)):
            event_type = int.from_bytes(byte[0:4], "little")
            ts_sec = int.from_bytes(byte[4:8], "little")
            ts_nsec = int.from_bytes(byte[8:12], "little")
            timestamp_us = ts_sec * 1000000 + ts_nsec / 1000.0
            tid = int.from_bytes(byte[12:16], "little")
            arg1 = int.from_bytes(byte[16:24], "little")
            arg2 = int.from_bytes(byte[24:32], "little")
            arg3 = int.from_bytes(byte[32:40], "little")

            if event_type == 1: # stack sample
                latency_us = arg1 / 1000.0
                pc = arg2
                ngen = arg3

                if tid not in thread_context:
                    continue

                timestamp_us -= latency_us
                if min_tsc == 0 or min_tsc > timestamp_us:
                    min_tsc = timestamp_us

                if max_tsc == 0 or max_tsc < timestamp_us + latency_us:
                    max_tsc = timestamp_us + latency_us

                if tid not in thread_list:
                    thread_list.append(tid)

                pc -= 5
                if pc not in finfo_cache:
                    finfo_cache[pc] = get_finfo(dwarfinfo, mapsinfo, pc)

                finfo = finfo_cache[pc]

                filter_req.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'event': "STACK_SAMPLE",
                    'detail': "ngen={:d}, latency={:f}, pc={}({})"
                            .format(ngen, latency_us, hex(pc), finfo)})

            elif event_type == 2: # tag set
                tag = arg1

                if tag != mreq and tid in thread_context:
                    thread_context.remove(tid)
                    filter_req.append({'tsc': timestamp_us,
                        'thread_idx': tid,
                        'event': "TAG_UNSET",
                        'detail': "new_tag={:d}".format(tag)})

                if tag == mreq and tid not in thread_context:
                    thread_context.append(tid)
                    filter_req.append({'tsc': timestamp_us,
                        'thread_idx': tid,
                        'event': "TAG_SET",
                        'detail': ""})

            elif event_type == 3: # tag block
                tag = arg1
                
                if tag == mreq and tid in thread_context:
                    thread_context.remove(tid)
                    filter_req.append({'tsc': timestamp_us,
                        'thread_idx': tid,
                        'event': "TAG_BLOCK",
                        'detail': ""})
    
    def filter_req_sort(e):
        return e['tsc']

    filter_req.sort(key=filter_req_sort)
    return filter_req, thread_list, min_tsc, max_tsc

def parse_perf(thread_list, min_tsc, max_tsc):
    print('Perf Data: {}'.format(PERF_DATA_FILENAME))
    if not os.path.exists(PERF_DATA_FILENAME):
        print('  Cannot find {}'.format(PERF_DATA_FILENAME))
        return []

    if not os.path.exists(PERF_DEC_FILENAME):
        if os.system('sudo perf sched script --ns -F -comm > {}'.format(PERF_DEC_FILENAME)) != 0:
            print('  [Error] Decoding perf failed. Please check the permission')
            return []
    
    row_in_time = []
    with open(PERF_DEC_FILENAME, "r") as perf_dec_file:
        csv_reader = csv.reader(perf_dec_file, skipinitialspace=True, delimiter=' ')
        for row in csv_reader:
            thread_id = int(row[0])
            cpu_id = int(row[1][1:-1])
            timestamp = float(row[2][:-1])
            timestamp_us = timestamp * 1000000
            event = row[3][:-1]
            bpf_output = " ".join(row[4:])
    
            skip = True

            if timestamp_us < min_tsc:
                continue

            if timestamp_us > max_tsc:
                break
    
            if thread_id in thread_list:
                skip = False
    
            for tid in thread_list:
                if "next_pid={:d}".format(tid) in row[4:] \
                        or "pid={:d}".format(tid) in row[4:]:
                    skip = False
    
            if skip:
                continue

            event_str = ""
            if "sched:sched_switch" in event:
                event_str = "SCHED_SWITCH"
            elif "sched:sched_waking" in event:
                event_str = "SCHED_WAKING"
            elif "sched:sched_migrate_task" in event:
                event_str = "SCHED_MIGRATE"
            else:
                continue

            row_in_time.append({'tsc': timestamp_us,
                'thread_idx': thread_id,
                'event': event_str,
                'detail': "cpu_id={:d}, {}".format(cpu_id, bpf_output)})
    return row_in_time

def generate_stats(executable, mreq):
    print('executable: {}'.format(executable))
    print("req ID = {:d}".format(mreq))

    filter_req, thread_list, min_tsc, max_tsc = parse_ldb(executable, mreq)
    row_in_time = parse_perf(thread_list, min_tsc, max_tsc)

    ldb_i = 0
    perf_i = 0

    while ldb_i < len(filter_req) and perf_i < len(row_in_time):
        le = filter_req[ldb_i]
        pe = row_in_time[perf_i]
        if le['tsc'] < pe['tsc']:
            print("{:f} (+{:f}) [{:d}] {} {}"
                    .format(le['tsc'], le['tsc'] - min_tsc, le['thread_idx'],
                        le['event'], le['detail']))
            ldb_i += 1
        else:
            print("{:f} (+{:f}) [{:d}] {} {}"
                .format(pe['tsc'], pe['tsc'] - min_tsc, pe['thread_idx'],
                    pe['event'], pe['detail']))
            perf_i += 1

    for e in filter_req[ldb_i:]:
        print("{:f} (+{:f}) [{:d}] {} {}"
                .format(e['tsc'], e['tsc'] - min_tsc, e['thread_idx'], e['event'], e['detail']))

    for e in row_in_time[perf_i:]:
        print("{:f} (+{:f}) [{:d}] {} {}"
              .format(e['tsc'], e['tsc'] - min_tsc, e['thread_id'], e['event'], e['detail']))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Expected usage: {0} <executable> <req#>'.format(sys.argv[0]))
        sys.exit(1)
    generate_stats(sys.argv[1], int(sys.argv[2]))
