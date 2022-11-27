import sys

LDB_DATA_FILENAME = "ldb.data"

def count_events():
    ecnt = [0] * 12
    with open(LDB_DATA_FILENAME, 'rb') as ldb_bin:
        while (byte := ldb_bin.read(40)):
            event_type = int.from_bytes(byte[0:4], "little")
            ecnt[event_type] += 1

    for i in range(12):
        print(i, ecnt[i])

if __name__ == '__main__':
    count_events()
