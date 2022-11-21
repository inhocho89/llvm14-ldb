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

from elftools.common.py3compat import bytes2str

LDB_DATA_FILENAME = "ldb.data"

def generate_stats(executable):
    start_us = {}
    finish_us = {}
    thread_context = {} # thread_id -> tag
    # collect latency informations
    with open(LDB_DATA_FILENAME, 'rb') as ldb_bin:
        while (byte := ldb_bin.read(40)):
            event_type = int.from_bytes(byte[0:4], "little")
            ts_sec = int.from_bytes(byte[4:8], "little")
            ts_nsec = int.from_bytes(byte[8:12], "little")
            timestamp_us = ts_sec * 1000000 + ts_nsec / 1000.0
            tid = int.from_bytes(byte[12:16], "little")
            arg1 = int.from_bytes(byte[16:24], "little")
            #arg2 = int.from_bytes(byte[24:32], "little")
            #arg3 = int.from_bytes(byte[32:40], "little")

            if event_type == 2: # tag set
                tag = arg1
                prev_tag = 0
                if tid in thread_context:
                    prev_tag = thread_context[tid]

                # mark finish
                if prev_tag != 0:
                    finish_us[prev_tag] = timestamp_us

                # mark start
                if tag != 0 and tag not in start_us:
                    start_us[tag] = timestamp_us

                thread_context[tid] = tag;

            elif event_type == 3: # tag block
                tag = arg1
                # mark finish
                if tag != 0:
                    finish_us[tag] = timestamp_us

                thread_context[tid] = 0

    latencies = []
    for nreq in start_us.keys():
        latencies.append({'nreq': nreq,
                          'latency': finish_us[nreq]-start_us[nreq]})

    def filter_req_sort(e):
        return e['latency']

    latencies.sort(key=filter_req_sort,reverse=True)

    for e in latencies:
        print("{:d}, {:f}".format(e['nreq'], e['latency']))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected usage: {0} <executable>'.format(sys.argv[0]))
        sys.exit(1)
    generate_stats(sys.argv[1])
