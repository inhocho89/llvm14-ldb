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

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.common.utils import bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

CYCLES_PER_US = 2992

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

def generate_stats(executable, ldb_raw, mreq):

    print('executable: {}'.format(executable))
    print('LDB data: {}'.format(ldb_raw))
    latencies = {}

    with open(executable, 'rb') as e:
        # get elf and dwarf information
        elffile = ELFFile(e)

        if not elffile.has_dwarf_info():
            print('  file has no debugging information')
            return

        dwarfinfo = elffile.get_dwarf_info()

        filter_req = []
        thread_dict = {}
        pc_buf = {}
        nthread = 0
        min_tsc = 0

        print("req ID = {:d}".format(mreq))
        # collect latency informations
        with open(ldb_raw, 'r') as ldb_raw_file:
            csv_reader = csv.reader(ldb_raw_file, delimiter=',')
            for row in csv_reader:
                if (len(row) != 6):
                    continue
                timestamp = int(row[0])
                thread_id = int(row[1])
                nreq = int(row[2])
                ngen = int(row[3])
                latency = int(row[4])
                pc = int(row[5],0)

                timestamp -= latency

                if nreq != mreq:
                    continue

                if min_tsc == 0 or min_tsc > timestamp:
                    min_tsc = timestamp

                if thread_id not in thread_dict:
                    thread_dict[thread_id] = nthread
                    nthread += 1
                
                thread_idx = thread_dict[thread_id]

                pc -= 5
                if pc not in pc_buf:
                    fname_, line_, col_ = decode_file_line(dwarfinfo, pc)
                    pc_buf[pc] = [fname_, line_, col_]

                fname, line, col = pc_buf[pc]

                if fname == None:
                    continue

                filter_req.append({'tsc': timestamp,
                    'thread_idx': thread_idx,
                    'ngen': ngen,
                    'latency': latency,
                    'pc': pc,
                    'fname': bytes2str(fname),
                    'line': line,
                    'col': col})
        
        def filter_req_sort(e):
            return e['tsc']

        filter_req.sort(key=filter_req_sort)

        for e in filter_req:
            print("{:f}, {:d}, {:d}, {:f}, {} ({}:{:d}:{:d})"
                    .format((e['tsc'] - min_tsc) / CYCLES_PER_US, e['thread_idx'], e['ngen'],
                        e['latency'] / CYCLES_PER_US, hex(e['pc']), e['fname'], e['line'], e['col']))

        """
        latencies_ordered = []
        for pc, larr in latencies.items():
            pc -= 5
            larr.sort()
            N = len(larr)
            latencies_ordered.append({'pc': pc, 'num_samples': N, 'median': larr[int(N * 0.5)],
                '90p': larr[int(N * 0.9)], '99p': larr[int(N * 0.99)], '999p': larr[int(N * 0.999)]})

        def dist_distance(e):
            return e['999p'] - e['median']

        latencies_ordered.sort(key=dist_distance, reverse=True)

        for e in latencies_ordered:
            fname, line, col = decode_file_line(dwarfinfo, e['pc'])
            if fname == None:
                continue

            print('{}:{:d}:{:d} (pc={})'.format(bytes2str(fname), line, col, hex(e['pc'])))
            print('    num_samples: {:d}'.format(e['num_samples']))
            print('    median: {:.4f}'.format(e['median']))
            print('    90p: {:.4f}'.format(e['90p']))
            print('    99p: {:.4f}'.format(e['99p']))
            print('    99.9p: {:.4f}'.format(e['999p']))
        """
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Expected usage: {0} <executable> <req#> <ldb raw output=ldb.data>'.format(sys.argv[0]))
        sys.exit(1)
    #addr = int(sys.argv[1], 0)
    ldb_raw = "ldb.data"
    if len(sys.argv) > 3:
        ldb_raw = argv[3]
    generate_stats(sys.argv[1], ldb_raw, int(sys.argv[2]))
    #process_file(sys.argv[2], addr)
