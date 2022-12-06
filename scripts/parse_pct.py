from __future__ import print_function
import sys
import os
import csv

from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

LDB_DATA_FILENAME = "ldb.data"

EVENT_STACK_SAMPLE = 1
EVENT_TAG_SET = 2
EVENT_TAG_BLOCK = 3
EVENT_TAG_UNSET = 4
EVENT_TAG_CLEAR = 5
EVENT_MUTEX_WAIT = 6
EVENT_MUTEX_LOCK = 7
EVENT_MUTEX_UNLOCK = 8
EVENT_JOIN_WAIT = 9
EVENT_JOIN_JOINED = 10

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

def get_req_id_pct(start_pct, end_pct):
    start_us = {}
    active_tags = {}
    latencies = []
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

            if event_type == EVENT_TAG_SET:
                tag = arg1

                if tag == 0:
                    continue

                # first set
                if tag not in active_tags:
                    start_us[tag] = timestamp_us
                    active_tags[tag] = []

                active_tags[tag].append(tid)

            elif event_type == EVENT_TAG_UNSET:
                tag = arg1

                if tag == 0 or tag not in active_tags:
                    continue

                if tid in active_tags[tag]:
                    active_tags[tag].remove(tid)

                # last unset
                if len(active_tags[tag]) == 0:
                    latencies.append({'nreq': tag,
                        'latency': timestamp_us - start_us[tag]})

                    active_tags.pop(tag)

            elif event_type == EVENT_TAG_CLEAR:
                for tag in list(active_tags.keys()):

                    if tid in active_tags[tag]:
                        active_tags[tag].remove(tid)

                    # last unset
                    if len(active_tags[tag]) == 0:
                        latencies.append({'nreq': tag,
                            'latency': timestamp_us - start_us[tag]})

                        active_tags.pop(tag)

    def filter_req_sort(e):
        return e['latency']

    latencies.sort(key=filter_req_sort)

    N = len(latencies)

    start_idx = int((N-1) * start_pct)
    end_idx = int((N-1) * end_pct)

    ret = []
    slat = 0.0
    for i in range(start_idx, end_idx):
        ret.append(latencies[i]['nreq'])
        slat += latencies[i]['latency']

    return ret, slat

def get_events_from_ldb(request_ids):
    thread_watch = []   # list of thread to watch
    events = []

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

            if event_type == EVENT_STACK_SAMPLE:
                latency_us = arg1 / 1000.0
                pc = arg2
                ngen = arg3

                if tid not in thread_watch:
                    continue

                pc -= 5

                # this is related event
                events.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'pc': pc,
                    'latency': latency_us,
                    'ngen': ngen})
            elif event_type == EVENT_TAG_SET:
                tag = arg1

                if tag not in request_ids:
                    continue

                if tid not in thread_watch:
                    thread_watch.append(tid)

            elif event_type == EVENT_TAG_BLOCK:
                tag = arg1

                if tag not in request_ids or tid not in thread_watch:
                    continue

                thread_watch.remove(tid)

            elif event_type == EVENT_TAG_UNSET:
                tag = arg1

                if tag not in request_ids or tid not in thread_watch:
                    continue

                thread_watch.remove(tid)

            elif event_type == EVENT_TAG_CLEAR:
                if tid not in thread_watch:
                    continue

                thread_watch.remove(tid)

    def events_sort_tsc(e):
        return e['tsc']

    events.sort(key=events_sort_tsc)

    return events

def generate_stat(executable, start_pct, end_pct):
    dwarfinfo = parse_elf(executable)
    mapsinfo = parse_maps()

    req_ids, total_latency = get_req_id_pct(start_pct, end_pct)
    events = get_events_from_ldb(req_ids)

    latencies = {}

    for e in events:
        if e['pc'] in latencies:
            latencies[e['pc']].append(e['latency'])
        else:
            latencies[e['pc']] = [e['latency']]

    latencies_ordered = []
    pcs = []
    for pc, larr in latencies.items():
        pc -= 5
        larr.sort()
        N = len(larr)
        if larr[N-1] == 0.0:
            continue
        s = sum(larr)
        latencies_ordered.append({'pc': pc, 'num_samples': N, 'median': larr[int((N-1) * 0.5)],
            '90p': larr[int((N-1) * 0.9)], '99p': larr[int((N-1) * 0.99)],
            '999p': larr[int((N-1) * 0.999)], 'max': larr[N-1], 'sum': s})
        pcs.append(pc)

    def dist_distance(e):
        return e['sum']

    latencies_ordered.sort(key=dist_distance, reverse=True)
    finfomap = get_finfos(dwarfinfo, mapsinfo, pcs)

    for e in latencies_ordered:
        print('{} (pc={})'.format(finfomap[e['pc']], hex(e['pc'])))
        print('    num_samples: {:d}'.format(e['num_samples']))
        print('    sum: {:.4f} ({:.2f})'.format(e['sum'], e['sum']/total_latency))
        print('    median: {:.4f}'.format(e['median']))
        print('    90p: {:.4f}'.format(e['90p']))
        print('    99p: {:.4f}'.format(e['99p']))
        print('    99.9p: {:.4f}'.format(e['999p']))
        print('    max: {:.4f}'.format(e['max']))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Expected usage: {0} <executable> <start_pct> <end_pct>'.format(sys.argv[0]))
        sys.exit(1)
    start_pct = float(sys.argv[2])
    end_pct = float(sys.argv[3])
    if start_pct > 1.0 or start_pct < 0.0 or end_pct > 1.0 or end_pct < 0.0:
        print('pct should be between 0.0 and 1.0')
    generate_stat(sys.argv[1], start_pct, end_pct)
