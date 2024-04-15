ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LDXX = $(ROOT_PATH)/build/bin/clang++
LLCXX = $(ROOT_PATH)/build/bin/llc
OPTXX = $(ROOT_PATH)/build/bin/opt

all: bench bench_orig

bench_orig: bench.cc
	/usr/bin/clang++ -pthread -O3 bench.cc -o bench_orig
#	/usr/bin/clang++ -pthread -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer bench.cc -o bench_orig

bench: bench.o
	$(CXX) bench.o -o bench -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer \
		-Wl,--unresolved-symbols=ignore-in-object-files
#	$(CXX) bench.cc -o bench -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer \
		-mllvm -enable-ldb-tls -Wl,--unresolved-symbols=ignore-in-object-files

bench.o: bench.cc
	$(CXX) bench.cc -c -o bench.o -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer

bench.s: bench.cc
	$(CXX) bench.cc -o bench.s -S -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer \
		-Wl,--unresolved-symbols=ignore-in-object-files

clean:
	rm bench.s bench.o bench bench_orig
