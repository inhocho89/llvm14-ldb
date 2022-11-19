ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LDXX = $(ROOT_PATH)/build/bin/clang++

LIBLDB = $(ROOT_PATH)/libldb/libldb.a

all: hello

hello: hello.o $(LIBLDB)
	$(CXX) -lpthread hello.o $(LIBLDB) -o hello

hello.o: hello.cc
	$(CXX) -O3 -fno-omit-frame-pointer -c hello.cc -o hello.o

hello.s: hello.cc
	$(CXX) -S -O3 -fno-omit-frame-pointer hello.cc -o hello.s

clean:
	rm hello
