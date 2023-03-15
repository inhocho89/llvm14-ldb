from __future__ import print_function
import sys, os

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

APP_DIR = ""

def generate_stats():
    start_us = {}
    active_tags = {}
    latencies = []
    # collect latency informations
    with open('{}/{}'.format(APP_DIR, LDB_DATA_FILENAME), 'rb') as ldb_bin:
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

    latencies.sort(key=filter_req_sort,reverse=True)
    N = len(latencies)

    with open('templates/index.html', 'w') as f:
        f.write("<html>\n")
        f.write("<title> LDB </title>\n")
        f.write("<body>\n")
        f.write("<h2> 100 Tails </h2>\n")
        f.write("<ul>\n")
        for e in latencies[0:100]:
            f.write('<li><a href="/req?id={:d}">{:d}</a>, {:.02f} us</li>\n'
                    .format(e['nreq'],e['nreq'], e['latency']))
        f.write("</ul>\n")
        f.write("<h2> Percentiles </h2>\n")
        f.write("<ul>\n")

        e = latencies[0]
        f.write('<li>[p100] <a href="/req?id={:d}">{:d}</a>, {:.02f} us</li>\n'
                .format(e['nreq'],e['nreq'], e['latency']))
        e = latencies[int((N-1) * 0.0001)]
        f.write('<li>[p99.99] <a href="/req?id={:d}">{:d}</a>, {:.02f} us</li>\n'
                .format(e['nreq'],e['nreq'], e['latency']))
        e = latencies[int((N-1) * 0.001)]
        f.write('<li>[p99.9] <a href="/req?id={:d}">{:d}</a>, {:.02f} us</li>\n'
                .format(e['nreq'],e['nreq'], e['latency']))

        for i in range(1, 101):
            e = latencies[int((N-1) * (i / 100))]
            f.write('<li>[p{:d}] <a href="/req?id={:d}">{:d}</a>, {:.02f} us</li>\n'
                    .format(100-i, e['nreq'],e['nreq'], e['latency']))
        f.write("</ul>\n")
        f.write("</body>\n")
        f.write("</html>\n")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected usage: {0} <APP_DIR>'.format(sys.argv[0]))
        sys.exit(1)
    APP_DIR = sys.argv[1]
    if not os.path.exists("{}/{}".format(APP_DIR, LDB_DATA_FILENAME)):
        print("Cannot find LDB data in {}".format(APP_DIR))
        sys.exit(1)
    generate_stats()
