from __future__ import print_function
import sys
import os

LDB_DATA_FILENAME = "ldb.data"
LDB_DATA_ORDERED_FILENAME = "ldb.data.ordered"

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
EVENT_THREAD_CREATE = 11
EVENT_THREAD_EXIT = 12

def generate_stats():
    if not os.path.exists(LDB_DATA_ORDERED_FILENAME) or \
            (os.path.getmtime(LDB_DATA_FILENAME) > os.path.getmtime(LDB_DATA_ORDERED_FILENAME)):
        all_events = []
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

                if event_type < EVENT_STACK_SAMPLE or event_type > EVENT_THREAD_EXIT:
                    continue

                all_events.append({'tsc': timestamp_us,
                    'event_type': event_type,
                    'tid': tid,
                    'arg1': arg1,
                    'arg2': arg2,
                    'arg3': arg3})
        
        all_events.sort(key=lambda entry: entry['tsc'])

        with open(LDB_DATA_ORDERED_FILENAME, 'wb') as ldb_bin:
            for event in all_events:
                ts_sec = int(event['tsc'] / 1000000)
                ts_nsec = int((event['tsc'] * 1000) % 1000000000)
                ldb_bin.write(event['event_type'].to_bytes(4, "little"))
                ldb_bin.write(ts_sec.to_bytes(4, "little"))
                ldb_bin.write(ts_nsec.to_bytes(4, "little"))
                ldb_bin.write(event['tid'].to_bytes(4, "little"))
                ldb_bin.write(event['arg1'].to_bytes(8, "little"))
                ldb_bin.write(event['arg2'].to_bytes(8, "little"))
                ldb_bin.write(event['arg3'].to_bytes(8, "little"))

    start_us = {}
    active_tags = {}
    latencies = []
    # collect latency informations
    with open(LDB_DATA_ORDERED_FILENAME, 'rb') as ldb_bin:
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
                    if timestamp_us - start_us[tag] > 0.0:
                        latencies.append({'nreq': tag,
                            'latency': timestamp_us - start_us[tag]})

                    active_tags.pop(tag)

            elif event_type == EVENT_TAG_CLEAR:
                for tag in list(active_tags.keys()):

                    if tid in active_tags[tag]:
                        active_tags[tag].remove(tid)

                    # last unset
                    if len(active_tags[tag]) == 0:
                        if timestamp_us - start_us[tag] > 0.0:
                            latencies.append({'nreq': tag,
                                'latency': timestamp_us - start_us[tag]})

                        active_tags.pop(tag)

    def filter_req_sort(e):
        return e['latency']

    latencies.sort(key=filter_req_sort,reverse=True)

    for e in latencies:
        print("{:d}, {:f}".format(e['nreq'], e['latency']))

if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Expected usage: {0}'.format(sys.argv[0]))
        sys.exit(1)
    generate_stats()
