ROOT_PATH = ../..
CC = $(ROOT_PATH)/build/bin/clang
CXX = $(ROOT_PATH)/build/bin/clang++
LIBLDB = $(ROOT_PATH)/libldb/libldb.a

LUCENE_PATH = ../../../LucenePlusPlus
LIBLUCENE = $(LUCENE_PATH)/build/src/core/liblucene++.a

LDB_LDFLAGS = -O3 -g -fdebug-default-version=3 -fno-omit-frame-pointer -lpthread \
							-lboost_iostreams -lboost_thread -lboost_filesystem -lboost_regex
LDB_CCFLAGS = -O3 -g -fdebug-default-version=3 -fno-omit-frame-pointer \
							-I$(ROOT_PATH)/libldb/include -I$(LUCENE_PATH)/include/lucene++ \
							-I$(LUCENE_PATH)/build/include

all: lucene-server

lucene-server: lucene-server.o $(LIBLDB) $(LIBLUCENE)
	$(CXX) $(LDB_LDFLAGS) -o $@ $^

lucene-server.o: lucene-server.cc
	$(CXX) $(LDB_CCFLAGS) -o $@ -c $<

clean:
	rm -f lucene-server.o lucene-server
