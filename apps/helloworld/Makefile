
ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
CXXORIG = /usr/bin/clang++
LDXX = $(ROOT_PATH)/build/bin/clang++

all: hello

hello: hello.cc
	$(CXX) hello.cc -o hello -O3 -fno-omit-frame-pointer -Wl,--unresolved-symbols=ignore-in-object-files
#	$(CXX) hello.cc -o hello -O3 -mllvm -enable-ldb-tls -fno-omit-frame-pointer

hello.ll: hello.cc
	$(CXX) -S -O3 -fno-omit-frame-pointer -emit-llvm hello.cc -o hello.ll

hello.s: hello.cc
	$(CXX) -S -O3 -fno-omit-frame-pointer hello.cc -o hello.s

hello.orig.s: hello.cc
	$(CXXORIG) -S -O3 -fno-omit-frame-pointer hello.cc -o hello.orig.s

clean:
	rm hello.s hello.orig.s hello
