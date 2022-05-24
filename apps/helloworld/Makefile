
ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LDXX = $(ROOT_PATH)/build/bin/clang++
LLCXX = $(ROOT_PATH)/build/bin/llc
OPTXX = $(ROOT_PATH)/build/bin/opt

all: hello

hello: hello.s
	$(LDXX) hello.s -o hello

hello.s: hello.ll
	$(LLCXX) hello.ll -o hello.s

hello.ll : hello_.ll
	$(OPTXX) -enable-new-pm=0 -load $(ROOT_PATH)/build/lib/LLVMLDB.so \
		-LDBDeclareTls -S hello_.ll -o hello.ll

hello_.ll: hello.cc
	$(CXX) -S -emit-llvm -O3 -fno-omit-frame-pointer hello.cc -o hello_.ll

clean:
	rm hello.s hello_.ll hello.ll hello
