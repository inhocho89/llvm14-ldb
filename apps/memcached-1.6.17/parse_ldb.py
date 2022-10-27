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

def generate_stats(executable, ldb_raw):

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

        # collect latency informations
        with open(ldb_raw, 'r') as ldb_raw_file:
            csv_reader = csv.reader(ldb_raw_file, delimiter=',')
            for row in csv_reader:
                if (len(row) != 6):
                    continue
                #timestamp = int(row[0])
                #thread_id = int(row[1])
                #tag = int(row[2])
                #ngen = int(row[3])
                latency = float(row[4])
                pc = int(row[5],0)

                if pc in latencies:
                    latencies[pc].append(latency)
                else:
                    latencies[pc] = [latency]

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
        # report latency distributions
        for pc, larr in latencies.items():
            # previous instruction
            pc -= 5
            larr.sort()
            N = len(larr)
            fname, line, col = decode_file_line(dwarfinfo, pc)
            if fname == None:
                continue
            print('{}:{:d}:{:d} (pc={})'.format(bytes2str(fname), line, col, hex(pc)))
            print('  num_samples: {:d}'.format(N))
            print('  median: {:.4f}'.format(larr[int(N * 0.5)]))
            print('  90p: {:.4f}'.format(larr[int(N * 0.9)]))
            print('  99p: {:.4f}'.format(larr[int(N * 0.99)]))
            print('  99.9p: {:.4f}'.format(larr[int(N * 0.999)]))
        """

        """
        for pc, larr in latencies.items():
            pc -= 5
            avg = larr[0]
            avg2 = larr[0] * larr[0]
            var = 0.0
            N = len(larr)

            fname, line, col = decode_file_line(dwarfinfo, pc)

            for i in range(1, N):
                if larr[i] > avg + 2 * math.sqrt(var):
                    print('{}:{:d}:{:d} (pc={}) took {:f} us (avg = {:f} us)'.format(bytes2str(fname), line, col, hex(pc), larr[i], avg))
                avg = 0.8 * avg + 0.2 * larr[i]
                avg2 = 0.8 * avg2 + 0.2 * larr[i] * larr[i]
                var = avg2 - avg * avg
        """

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Expected usage: {0} <executable> <ldb raw output=ldb.data>'.format(sys.argv[0]))
        sys.exit(1)
    #addr = int(sys.argv[1], 0)
    ldb_raw = "ldb.data"
    if len(sys.argv) > 2:
        ldb_raw = argv[2]
    generate_stats(sys.argv[1], ldb_raw)
    #process_file(sys.argv[2], addr)
