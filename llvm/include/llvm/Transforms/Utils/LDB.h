//===-- LDB.h - Passes related to Latency Debugger --------*- C++ -*-===//

#ifndef LLVM_TRANSFORMS_UTILS_LDB_H
#define LLVM_TRANSFORMS_UTILS_LDB_H

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

namespace llvm {
class LDBTLSPass : public PassInfoMixin<LDBTLSPass> {
public:
  LDBTLSPass() = default;

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};
} // namespace llvm

#endif // LLVM_TRANSFORMS_UTILS_LDB_H
