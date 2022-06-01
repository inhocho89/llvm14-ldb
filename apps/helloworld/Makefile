
ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LDXX = $(ROOT_PATH)/build/bin/clang++
LLCXX = $(ROOT_PATH)/build/bin/llc
OPTXX = $(ROOT_PATH)/build/bin/opt

all: hello

hello: hello.s
	$(LDXX) hello.s -o hello

hello.s: hello.cc
	$(CXX) -S -O3 -mllvm -enable-ldb-tls -fno-omit-frame-pointer hello.cc -o hello.s

clean:
	rm hello.s hello
