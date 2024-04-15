ROOT_PATH=../..
CXX = $(ROOT_PATH)/build/bin/clang++
LIBLDB = $(ROOT_PATH)/libldb/libldb.a

all: demo

demo: demo.o $(LIBLDB)
	$(CXX) $^ -stdlib=libc++ -lpthread -o $@

demo.o: demo.cc
	$(CXX) -g -O3 -fno-omit-frame-pointer -fdebug-default-version=3 -stdlib=libc++ -I$(ROOT_PATH)/ -I$(ROOT_PATH)/libldb/include -c $< -o $@

clean:
	rm demo.o demo maps.data ldb.data ldb.data.ordered snapshot.txt
