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

from elftools.common.utils import bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

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
    return None, None, None

def generate_stats(executable, mreq, ldb_raw, perf_raw):
    latencies = {}
    perf_decode = ""
    print('executable: {}'.format(executable))
    print('LDB data: {}'.format(ldb_raw))
    print('Perf data: {}'.format(perf_raw))
    perf_decode = "perf.dec"
    if os.path.exists(perf_raw):
        if not os.path.exists(perf_decode):
            print('  generating decoded data...')
            if(os.system('sudo perf sched script -F time,tid,cpu,event,ip,sym > {}'.format(perf_decode)) != 0):
                print('[Error] Decoding perf data failed. Please check the permission')
            print('  generated {}'.format(perf_decode))
        else:
            print('  {} already exists'.format(perf_decode))
    else:
        perf_decode = ""
        print('  Cannot find perf data')

    with open(executable, 'rb') as e:
        # get elf and dwarf information
        elffile = ELFFile(e)

        if not elffile.has_dwarf_info():
            print('  file has no debugging information')
            return

        dwarfinfo = elffile.get_dwarf_info()

        filter_req = []
        thread_list = []
        pc_buf = {}
        nthread = 0
        min_tsc = 0
        max_tsc = 0

        print("req ID = {:d}".format(mreq))
        # collect latency informations
        with open(ldb_raw, 'r') as ldb_raw_file:
            csv_reader = csv.reader(ldb_raw_file, delimiter=',')
            for row in csv_reader:
                if (len(row) != 7):
                    continue
                timestamp = float(row[0])
                timestamp_us = timestamp * 1000
                thread_id = int(row[1])
                nreq = int(row[2])
                ngen = int(row[3])
                latency = int(row[4])
                latency_us = latency / 1000.0
                pc = int(row[5],0)

                timestamp_us -= latency_us

                if nreq != mreq:
                    continue

                if min_tsc == 0 or min_tsc > timestamp_us:
                    min_tsc = timestamp_us

                if max_tsc == 0 or max_tsc < timestamp_us:
                    max_tsc = timestamp_us

                if thread_id not in thread_list:
                    thread_list.append(thread_id)

                pc -= 5
                if pc not in pc_buf:
                    fname_, line_, col_ = decode_file_line(dwarfinfo, pc)
                    pc_buf[pc] = [fname_, line_, col_]

                fname, line, col = pc_buf[pc]

                if fname == None:
                    continue

                filter_req.append({'tsc': timestamp_us,
                    'thread_idx': thread_id,
                    'ngen': ngen,
                    'latency': latency_us,
                    'pc': pc,
                    'fname': bytes2str(fname),
                    'line': line,
                    'col': col})
        
        def filter_req_sort(e):
            return e['tsc']

        filter_req.sort(key=filter_req_sort)

        with open(perf_decode, "r") as perf_dec_file:
            csv_reader = csv.reader(perf_dec_file, skipinitialspace=True, delimiter=' ')
            row_in_time = []
            prow = None
            for row in csv_reader:
                thread_id = int(row[0])
                cpu_id = int(row[1][1:-1])
                timestamp = float(row[2][:-1])
                timestamp_us = timestamp * 1000
                event = row[3][:-1]
                bpf_output = " ".join(row[4:])

                skip = True

                if thread_id in thread_list:
                    skip = False

                for tid in thread_list:
                    if "next_pid={:d}".format(tid) in row[4:] \
                            or "pid={:d}".format(tid) in row[4:]:
                        skip = False

                if skip:
                    continue

                if timestamp_us > max_tsc:
                    break

                if timestamp_us < min_tsc:
                    prow = {'tsc': timestamp_us,
                            'thread_id': thread_id,
                            'cpu_id': cpu_id,
                            'event': event,
                            'bpf_output': bpf_output}
                    continue

                if len(row_in_time) == 0 and prow != None:
                    row_in_time.append(prow)

                row_in_time.append({'tsc': timestamp_us,
                                    'thread_id': thread_id,
                                    'cpu_id': cpu_id,
                                    'event': event,
                                    'bpf_output': bpf_output})



        ldb_i = 0
        perf_i = 0

        while ldb_i < len(filter_req) and perf_i < len(row_in_time):
            le = filter_req[ldb_i]
            pe = row_in_time[perf_i]
            if le['tsc'] < pe['tsc']:
                print("{:f} (+{:f}), {:d}, {:d}, {:f}, {} ({}:{:d}:{:d})"
                        .format(le['tsc'], le['tsc'] - min_tsc, le['thread_idx'], le['ngen'],
                            le['latency'], hex(le['pc']), le['fname'],
                                le['line'], le['col']))
                ldb_i += 1
            else:
                print("**  {:f} (+{:f}), {:d}, {:d}, {}, {}"
                    .format(pe['tsc'], pe['tsc'] - min_tsc, pe['thread_id'], pe['cpu_id'],
                            pe['event'], pe['bpf_output']))
                perf_i += 1

        for e in filter_req[ldb_i:]:
            print("{:f} (+{:f}), {:d}, {:d}, {:f}, {} ({}:{:d}:{:d})"
                    .format(e['tsc'], e['tsc'] - min_tsc, e['thread_idx'], e['ngen'],
                        e['latency'], hex(e['pc']), e['fname'], e['line'], e['col']))

        for e in row_in_time[perf_i:]:
            print("**  {:f} (+{:f}), {:d}, {:d}, {}, {}"
                  .format(e['tsc'], e['tsc'] - min_tsc, e['thread_id'], e['cpu_id'],
                          e['event'], e['bpf_output']))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Expected usage: {0} <executable> <req#> <ldb raw output=ldb.data> <perf raw output=perf.data>'.format(sys.argv[0]))
        sys.exit(1)
    #addr = int(sys.argv[1], 0)
    ldb_raw = "ldb.data"
    perf_raw = "perf.data"
    if len(sys.argv) > 3:
        ldb_raw = argv[3]
    if len(sys.argv) > 4:
        perf_raw = argv[4]
    generate_stats(sys.argv[1], int(sys.argv[2]), ldb_raw, perf_raw)
    #process_file(sys.argv[2], addr)
