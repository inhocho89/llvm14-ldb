
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

bench.s: bench.cc
	$(CXX) bench.cc -o bench.s -S -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer \
		-mllvm -enable-ldb-tls

clean:
	rm bench.s bench bench_orig
