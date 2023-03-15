# Tail Latency Debugger

## Quick start

### System Build
1. Clone this repository

  * ``git clone git@github.com:inhocho89/llvm14-ldb.git``

2. Compile LLVM
  * ``llvm14-ldb> mkdir build``
  * ``llvm14-ldb> cd build``
  * ``llvm14-ldb/build> cmake -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_TARGET_ARCH=X86 -DCMAKE_BUILD_TYPE="Release" -DLLVM_BUILD_EXAMPLES=1 -DLLVM_INCLUDE_EXAMPLES=1 -DLLVM_ENABLE_PROJECTS="clang" -G "Unix Makefiles" ../llvm``
  * ``llvm14-ldb/build> cmake --build . -j``

3. Compile LDB library
  * ``llvm14-ldb/build> cd ../libldb``
  * ``llvm14-ldb/libldb> make``

### Running sample application (Please take a look apps/demo/Makefile to see how to write Makefile)
1. Compile sample application
  * ``llvm14-ldb> cd apps/demo``
  * ``llvm14-ldb/apps/demo> make``

2. (optional) run perf to get Linux scheduling data (in a separate terminal)
  * ``llvm14-ldb/apps/demo> sudo perf sched record -k CLOCK_MONOTONIC_RAW``

3. Run application with preloading LDB shim layer.
  * ``llvm14-ldb/apps/demo> LD_PRELOAD=/path/to/llvm14-ldb/libldb/libshim.so ./demo``

4. When enough data is collected (when the application exits), stop the perf

### Parsing the data
The raw data is in ldb.data (by LDB) and perf.data (by perf).
1. Parsing latency distribution for each function (this will only use LDB data)
  * ``llvm14-ldb/apps/demo> python3 ../../scripts/parse_summary.py demo > summary``

2. Parsing timeline of a request
  * ``llvm14-ldb/apps/demo> python3 ../../scripts/parse_req.py demo 100 > req100``
