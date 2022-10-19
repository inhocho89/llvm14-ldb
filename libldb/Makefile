ROOT_PATH=..
CXX = $(ROOT_PATH)/build/bin/clang++
CC = $(ROOT_PATH)/build/bin/clang
GCC = /usr/bin/gcc

all: ldb_init.o ldb_shim.so

ldb_shim.so: ldb_shim.c
	$(CC) -shared -g -fdebug-default-version=3 -fno-omit-frame-pointer -fpic -ldl -lpthread ldb_shim.c -o ldb_shim.so

ldb_init.o: ldb_init.c
	$(CC) -O3 -g -fdebug-default-version=3 -fno-omit-frame-pointer -c ldb_init.c -o ldb_init.o

ldb_init.ll: ldb_init.c
	$(CC) -O3 -g -fno-omit-frame-pointer -S -emit-llvm ldb_init.c -o ldb_init.ll

clean:
	rm ldb_init.o ldb_shim.so
