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
import svgwrite

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
                    fe = lineprog['file_entry'][prevstate.file - offset]
                    dir_path = b'.'
                    if fe.dir_index > 0:
                        dir_path = lineprog['include_directory'][fe.dir_index - 1]
                    ret[addr] = {'fname': fe.name,
                            'dir': dir_path,
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

def extract_func_desc(line):
    i = 0

    while i < len(line) and line[i] != '(':
        i += 1
    i += 1
    pending = 1
    while pending > 0 and i < len(line):
        if line[i] == ')':
            pending -= 1
        elif line[i] == '(':
            pending += 1
        i += 1

    if pending == 0:
        i -= 1
    i = min(i, len(line) - 1)
    return line[:i+1]

def func_read(file_path, nline, ncol):
    with open(file_path, "r") as f:
        for i, line in enumerate(f):
            if i == nline - 1:
                return extract_func_desc(line[ncol-1:])

    return "???"

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
        func_desc = func_read(bytes2str(ret[key]['dir']) + "/" + bytes2str(ret[key]['fname']),
                ret[key]['line'], ret[key]['col'])
        finfomap[key] = "{} ({}:{:d}:{:d})"\
                .format(func_desc, bytes2str(ret[key]['fname']),
                        ret[key]['line'], ret[key]['col'])

    # decode dynamic addresses
    ret = decode_dynamic(mapsinfo, addresses)

    for key in ret:
        finfomap[key] = "{}+{}".format(ret[key]['fname'], hex(ret[key]['offset']))

    return finfomap

def parse_ldb(executable, mreq):
#    print('LDB Data: {}'.format(LDB_DATA_FILENAME))
    dwarfinfo = parse_elf(executable)
    mapsinfo = parse_maps()

    my_events = []      # list of related event entries
    thread_list = []    # list of thread related to mreq
    thread_watch = []   # list of thread to watch
    thread_pending = {}
    pcs = []
    nthread = 0
    min_tsc = 0
    max_tsc = 0
    last_mutex_ts = {}

    all_events = []     # all the events happend while tag is set
    my_mwait_events = []

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

            if len(thread_watch) > 0:
                all_events.append({'tsc': timestamp_us,
                    'event_type': event_type,
                    'tid': tid,
                    'arg1': arg1,
                    'arg2': arg2,
                    'arg3': arg3})

            if event_type == EVENT_STACK_SAMPLE:
                latency_us = arg1 / 1000.0
                pc = arg2
                ngen = arg3
                event_str = ""
                detail_str = ""

                if tid not in thread_watch and tid not in thread_pending:
                    continue

                if tid in thread_pending and timestamp_us - latency_us > thread_pending[tid]:
                    thread_pending.pop(tid)
                    continue

                # my event
                if min_tsc == 0 or min_tsc > timestamp_us:
                    min_tsc = timestamp_us

                if max_tsc == 0 or max_tsc < timestamp_us:
                    max_tsc = timestamp_us

                if tid not in thread_list:
                    thread_list.append(tid)

                detail_str = "ngen={:d}, latency={:.3f} us".format(ngen, latency_us)

                pc -= 5

                # this is my event
                my_events.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'pc': pc,
                    'ngen': ngen,
                    'latency_us': latency_us,
                    'event': "STACK_SAMPLE",
                    'detail': detail_str})

                if pc not in pcs:
                    pcs.append(pc)

            elif event_type == EVENT_TAG_SET:
                tag = arg1

                if tag != mreq:
                    continue

                if tid not in thread_watch:
                    thread_watch.append(tid)

                my_events.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'pc': 0,
                    'event': "TAG_SET",
                    'detail': ""})

                if min_tsc == 0 or min_tsc > timestamp_us:
                    min_tsc = timestamp_us

            elif event_type == EVENT_TAG_BLOCK:
                tag = arg1

                if tag != mreq or tid not in thread_watch:
                    continue

                thread_watch.remove(tid)
                my_events.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'pc': 0,
                    'event': "TAG_BLOCK",
                    'detail': ""})

            elif event_type == EVENT_TAG_UNSET:
                tag = arg1

                if tag != mreq or tid not in thread_watch:
                    continue
                
                thread_watch.remove(tid)
                thread_pending[tid] = timestamp_us
                my_events.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'pc': 0,
                    'event': "TAG_UNSET",
                    'detail': ""})

            elif event_type == EVENT_TAG_CLEAR:
                if tid not in thread_watch:
                    continue

                thread_watch.remove(tid)
                thread_pending[tid] = timestamp_us
                my_events.append({'tsc': timestamp_us,
                    'thread_idx': tid,
                    'pc': 0,
                    'event': "TAG_CLEAR",
                    'detail': ""})

            elif event_type == EVENT_MUTEX_WAIT:
                mutex = arg1
                if tid in thread_watch:
                    my_events.append({'tsc': timestamp_us,
                        'thread_idx': tid,
                        'pc': 0,
                        'event': "MUTEX_WAIT",
                        'detail': "mutex={}".format(hex(mutex))})
                    last_mutex_ts[tid] = timestamp_us

            elif event_type == EVENT_MUTEX_LOCK:
                mutex = arg1
                if tid in thread_watch:
                    wait_time = -1.0
                    if tid in last_mutex_ts:
                        wait_time = timestamp_us - last_mutex_ts[tid]
                    my_events.append({'tsc': timestamp_us,
                        'thread_idx': tid,
                        'pc': 0,
                        'event': "MUTEX_LOCK",
                        'detail': "mutex={}, wait_time={:.3f} us"\
                                .format(hex(mutex), wait_time)})
                    my_mwait_events.append({'wait_tsc': last_mutex_ts[tid],
                        'lock_tsc': timestamp_us,
                        'tid': tid,
                        'mutex': mutex})
                    last_mutex_ts[tid] = timestamp_us

            elif event_type == EVENT_MUTEX_UNLOCK:
                mutex = arg1
                if tid in thread_watch:
                    lock_time = -1.0
                    if tid in last_mutex_ts:
                        lock_time = timestamp_us - last_mutex_ts[tid]
                    my_events.append({'tsc': timestamp_us,
                        'thread_idx': tid,
                        'pc': 0,
                        'event': "MUTEX_UNLOCK",
                        'detail': "mutex={}, lock_time={:f} us"\
                                .format(hex(mutex), lock_time)})
                    if tid in last_mutex_ts:
                        last_mutex_ts.pop(tid)

    def events_sort_tsc(e):
        return e['tsc']

    def events_sort_mwait(e):
        return e['wait_tsc']

    all_events.sort(key=events_sort_tsc)
    my_mwait_events.sort(key=events_sort_mwait)

    my_events.sort(key=events_sort_tsc)

    # parse pcs
    finfomap = get_finfos(dwarfinfo, mapsinfo, pcs)

    # update event detail
    for e in my_events:
        if e['pc'] == 0:
            continue
        e['detail'] += ", pc={}({})".format(hex(e['pc']), finfomap[e['pc']])
        e['fline'] = finfomap[e['pc']]

    return my_events, thread_list, min_tsc, max_tsc

def parse_perf(thread_list, min_tsc, max_tsc):
#    print('Perf Data: {}'.format(PERF_DATA_FILENAME))
    if not os.path.exists(PERF_DATA_FILENAME):
        print('  Cannot find {}'.format(PERF_DATA_FILENAME))
        return []

    if not os.path.exists(PERF_DEC_FILENAME) or \
            os.stat(PERF_DEC_FILENAME).st_mtime < os.stat(PERF_DATA_FILENAME).st_mtime:
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

SVG_WIDTH = 1200
SVG_HEIGHT = 500
XMARKS = 8
BAR_COLORS = ['rgb(216, 10, 44)',
        'rgb(241,38,27)',
        'rgb(226,116,36)',
        'rgb(208,139,35)',
        'rgb(214,170,7)',
        'rgb(254,172,35)',
        'rgb(207,182,42)',
        'rgb(213,216,26)',
        'rgb(220,224,32)',
        'rgb(256,256,256)']

def addBar(dwg, x, y, width, height, text, fill):
    g = dwg.g()
    
    # rect
    g.add(dwg.rect((x,y),(width,height), rx=2, ry=2, fill=fill))

    # text
    if len(text) * 7 > width - 3:
        tlen = (width - 3) // 7
        if tlen > 2:
            text = text[0:tlen-2] + ".."
        else:
            text = ""

    if len(text) > 0:
        g.add(dwg.text(text,
            insert=(x + 3,y + height - 3),
            font_size='12px',
            font_family='Courier New'))

    dwg.add(g)

def generate_stats(executable, mreq):
    filter_req, thread_list, min_tsc, max_tsc = parse_ldb(executable, mreq)
    row_in_time = parse_perf(thread_list, min_tsc, max_tsc)

    thread_id = thread_list[0]
    duration = max_tsc - min_tsc

    func_events = list(filter(lambda e: e['event'] == 'STACK_SAMPLE', filter_req))
    func_events = list(filter(lambda e: e['latency_us'] > 0.0, func_events))
    func_events = list(filter(lambda e: e['thread_idx'] == thread_id, func_events))

    def events_sort_ngen(e):
        return e['ngen']

    func_events.sort(key=events_sort_ngen)

    ## Draw SVG
    dwg = svgwrite.Drawing("req" + str(mreq) + ".svg", size=(SVG_WIDTH,SVG_HEIGHT))

    # draw background
    vert_grad = svgwrite.gradients.LinearGradient(start=(0, 0), end=(0,1), id="background")
    vert_grad.add_stop_color(offset='5%', color='#eeeeee', opacity=None)
    vert_grad.add_stop_color(offset='95%', color='#eeeeb0', opacity=None)
    dwg.defs.add(vert_grad)

    dwg.add(dwg.rect((0,0),(SVG_WIDTH,SVG_HEIGHT),fill="url(#background)"))

    # draw label
    dwg.add(dwg.text("Req ID = " + str(mreq),
        insert = (20, 20),
        font_size="12px",
        font_family="Courier New",
        font_weight="bold"))

    # draw x axis
    dwg.add(dwg.line(start=(50,SVG_HEIGHT-50),end=(SVG_WIDTH-20,SVG_HEIGHT-50),
        stroke="#000",fill="none",stroke_width=2))

    spacing = (SVG_WIDTH-70) / (XMARKS-1)
    spacingx = duration / (XMARKS-1)

    dwg.add(dwg.line(start=(50,SVG_HEIGHT-50-5),end=(50,SVG_HEIGHT-50+5),
        stroke="#000",fill="none",stroke_width=2))
    dwg.add(dwg.text("{:.0f} us".format(0.0),
        insert=(50 - 10,SVG_HEIGHT-50+20),font_size="12px",font_family="Courier New"))

    for i in range(1, XMARKS):
            dwg.add(dwg.line(start=(50 + spacing * i,SVG_HEIGHT-50-5),
                end=(50 + spacing * i,SVG_HEIGHT-50+5),
                stroke="#000",fill="none",stroke_width=2))
            dwg.add(dwg.text("{:.0f} us".format(i * spacingx),
                insert=(50 + spacing * i - 20,SVG_HEIGHT-50+20),
                font_size="12px",font_family="Courier New"))

    # draw function bars
    max_level = 0
    for i in range(len(func_events)):
        le = func_events[i]
        end = le['tsc'] - min_tsc
        start = end - le['latency_us']
        level = 0

        for j in range(i):
            le_ = func_events[j]
            end_ = le_['tsc'] - min_tsc
            start_ = end_ - le_['latency_us']
            if end_ > start and start_ < end:
                level += 1

        if level > max_level:
            max_level = level
        
        addBar(dwg,
                50 + (SVG_WIDTH-70) * start / duration, # x
                434 - level * 16, # y
                (SVG_WIDTH-70) * le['latency_us'] / duration, # width
                15, # height
                le['fline'],
                BAR_COLORS[level % len(BAR_COLORS)])

    # draw y axis
    yaxis_x = 30
    yaxis_y = SVG_HEIGHT - 50 - (max_level+1) * 8 + 35
    pcRotate = 'rotate(270,{:d},{:d})'.format(yaxis_x,yaxis_y)
    dwg.add(dwg.text("tid:" + str(thread_id),
        insert=(yaxis_x, yaxis_y),
        font_size="12px",
        font_family="Courier New",
        font_weight="bold",
        transform=pcRotate))

    dwg.save()

#    i = 0
#    while i < len(func_events):
#        le = func_events[i]
#        print("{:.3f} (+{:.3f}) [{:d}] {} {}"
#                .format(le['tsc'], le['tsc'] - min_tsc, le['thread_idx'],
#                    le['event'], le['detail']))
#        i += 1

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Expected usage: {0} <executable> <req#>'.format(sys.argv[0]))
        sys.exit(1)
    generate_stats(sys.argv[1], int(sys.argv[2]))
