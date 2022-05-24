
ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LDXX = $(ROOT_PATH)/build/bin/clang++
LLCXX = $(ROOT_PATH)/build/bin/llc
OPTXX = $(ROOT_PATH)/build/bin/opt

all: bench bench_orig

bench_orig: bench.cc
	clang++ -pthread -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer bench.cc -o bench_orig

bench: bench.s
	$(LDXX) -pthread bench.s -o bench

bench.s: bench.ll
	$(LLCXX) bench.ll -o bench.s

bench.ll : bench_.ll
	$(OPTXX) -enable-new-pm=0 -O3 -load $(ROOT_PATH)/build/lib/LLVMLDB.so \
		-LDBDeclareTls -S bench_.ll -o bench.ll

bench_.ll: bench.cc
	$(CXX) -S -emit-llvm -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer bench.cc -o bench_.ll

clean:
	rm bench.s bench_.ll bench.ll bench bench_orig
