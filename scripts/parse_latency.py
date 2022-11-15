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

def generate_stats(executable, ldb_raw):

    start_us = {}
    finish_us = {}

    # collect latency informations
    with open(ldb_raw, 'r') as ldb_raw_file:
        csv_reader = csv.reader(ldb_raw_file, delimiter=',')
        for row in csv_reader:
            if (len(row) != 7):
                continue
            #thread_id = int(row[1])
            #tag = int(row[2])
            #ngen = int(row[3])
            timestamp = float(row[0])
            timestamp_us = timestamp * 1000000
            nreq = int(row[2])
            latency = float(row[4])
            latency_us = latency / 1000.0
            pc = int(row[5],0)

            if nreq == 0:
                continue

            if nreq in start_us:
                finish_us[nreq] = max(finish_us[nreq], timestamp_us + latency_us)
            else:
                start_us[nreq] = timestamp_us
                finish_us[nreq] = timestamp_us + latency_us

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
    if len(sys.argv) < 2:
        print('Expected usage: {0} <executable> <ldb raw output=ldb.data>'.format(sys.argv[0]))
        sys.exit(1)
    #addr = int(sys.argv[1], 0)
    ldb_raw = "ldb.data"
    if len(sys.argv) > 2:
        ldb_raw = argv[2]
    generate_stats(sys.argv[1], ldb_raw)
    #process_file(sys.argv[2], addr)
