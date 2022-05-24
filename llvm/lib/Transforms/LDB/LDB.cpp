// ===- LDB.cpp - Create Thread-local global variable for LDB -----------===//

#include "llvm/IR/Constant.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

using namespace llvm;

#define DEBUG_TYPE "ldb"

namespace {

struct LDBDeclareTlsPass : public ModulePass {
  static char ID; // Pass identification

  LDBDeclareTlsPass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    Type *NgenTy = Type::getInt64Ty(M.getContext());
    M.getOrInsertGlobal("__ldb_ngen", NgenTy, [&] {
      GlobalVariable *g =
        new GlobalVariable(M, NgenTy, false, GlobalVariable::ExternalLinkage,
			   nullptr, "__ldb_ngen", nullptr,
			   GlobalVariable::GeneralDynamicTLSModel);
	g->setInitializer(Constant::getNullValue(NgenTy));
	g->setDSOLocal(true);
	g->setAlignment(llvm::Align(8));
	return g;
    });

    Type *RbpTy = Type::getInt8PtrTy(M.getContext());
    M.getOrInsertGlobal("__ldb_rbp", RbpTy, [&] {
      GlobalVariable *g =
        new GlobalVariable(M, RbpTy, false, GlobalVariable::ExternalLinkage,
			   nullptr, "__ldb_rbp", nullptr,
			   GlobalVariable::GeneralDynamicTLSModel);
	g->setInitializer(Constant::getNullValue(RbpTy));
	g->setDSOLocal(true);
	g->setAlignment(llvm::Align(8));
	return g;
    });

    return true;
  }
};

} // namespace

char LDBDeclareTlsPass::ID = 0;
static RegisterPass<LDBDeclareTlsPass>
X("LDBDeclareTls", "LDB - declare required global variables");
