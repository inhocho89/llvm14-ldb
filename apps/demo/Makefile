ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LIBLDB = $(ROOT_PATH)/libldb/libldb.a

all: demo demo_para

demo: demo.o $(LIBLDB)
	$(CXX) demo.o $(LIBLDB) -o demo

demo_para: demo_para.o $(LIBLDB)
	$(CXX) -g -fdebug-default-version=3 demo_para.o $(LIBLDB) -o demo_para

demo_para.s: demo_para.cc
	$(CXX) demo_para.cc -o demo_para.s -S -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer

demo.o: demo.cc
	$(CXX) -g -O3 -fdebug-default-version=3 -fno-optimize-sibling-calls -fno-omit-frame-pointer \
		-I$(ROOT_PATH)/libldb/include -c demo.cc -o demo.o

demo_para.o: demo_para.cc
	$(CXX) -g -O3 -fdebug-default-version=3 -fno-optimize-sibling-calls -fno-omit-frame-pointer \
		-I$(ROOT_PATH)/libldb/include -c demo_para.cc -o demo_para.o

demo.ll: demo.cc
	$(CXX) -g -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer -S -emit-llvm demo.cc

demo.s: demo.cc
	$(CXX) demo.cc -o demo.s -S -O3 -fno-optimize-sibling-calls -fno-omit-frame-pointer

clean:
	rm demo.o demo_para.o demo demo_para
