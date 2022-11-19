ROOT_PATH=..
CXX = $(ROOT_PATH)/build/bin/clang++
CC = $(ROOT_PATH)/build/bin/clang
GCC = /usr/bin/gcc
AR = /usr/bin/ar

LDB_CFLAGS = -O3 -g -fdebug-default-version=3 -fno-omit-frame-pointer -I./include

all: libshim.so libldb.a

libldb.a: hook.o logger.o monitor.o event.o tag.o
	$(AR) qc $@ $^

libshim.so: shim.o event.o
	$(CC) -shared -lpthread -ldl -o $@ $^

shim.o: shim.c
	$(CC) -O1 -g -fdebug-default-version=3 -fno-omit-frame-pointer -fPIC -o $@ -c $<

hook.o: hook.c
	$(CC) $(LDB_CFLAGS) -o $@ -c $<

logger.o: logger.c
	$(CC) $(LDB_CFLAGS) -o $@ -c $<

monitor.o: monitor.c
	$(CC) $(LDB_CFLAGS) -o $@ -c $<

tag.o: tag.c
	$(CC) $(LDB_CFLAGS) -o $@ -c $<

event.o: event.c
	$(CC) $(LDB_CFLAGS) -o $@ -c $<

clean:
	rm event.o monitor.o logger.o hook.o shim.o libshim.so libldb.a
