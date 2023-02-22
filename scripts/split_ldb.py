import os
import sys

def split_ldb(split_time):
    min_tsc = 0.0
    max_tsc = 0.0
    with open("ldb.data", 'rb') as ldb_bin:
        with open("ldb2.data", 'wb') as before_ldb:
            with open("ldb.tmp", 'wb') as after_ldb:
                while (byte := ldb_bin.read(40)):
                    ts_sec = int.from_bytes(byte[4:8], "little")
                    ts_nsec = int.from_bytes(byte[8:12], "little")
                    timestamp_s = ts_sec + ts_nsec / 1000000000.0

                    if min_tsc == 0.0 or min_tsc > timestamp_s:
                        min_tsc = timestamp_s

                    if max_tsc == 0.0 or max_tsc < timestamp_s:
                        max_tsc = timestamp_s

                    if timestamp_s < split_time:
                        before_ldb.write(byte)
                    else:
                        after_ldb.write(byte)

    os.rename("ldb.tmp", "ldb.data")
    print(min_tsc, max_tsc)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected usage: {0} <split_time>'.format(sys.argv[0]))
        sys.exit(1)
    split_ldb(float(sys.argv[1]))
