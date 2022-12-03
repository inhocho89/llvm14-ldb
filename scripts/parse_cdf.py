from __future__ import print_function
import sys

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

def generate_stats():
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
                    latencies.append(timestamp_us - start_us[tag])

                    active_tags.pop(tag)

            elif event_type == EVENT_TAG_CLEAR:
                for tag in list(active_tags.keys()):

                    if tid in active_tags[tag]:
                        active_tags[tag].remove(tid)

                    # last unset
                    if len(active_tags[tag]) == 0:
                        latencies.append(timestamp_us - start_us[tag])

                        active_tags.pop(tag)

    latencies.sort()

    N = len(latencies)

    for i_ in range(1001):
        i = i_ / 1000.0
        print("{:f}, {:f}".format(i, latencies[int((N-1) * i)]))

if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Expected usage: {0}'.format(sys.argv[0]))
        sys.exit(1)
    generate_stats()
