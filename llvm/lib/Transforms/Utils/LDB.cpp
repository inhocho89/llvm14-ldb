//===- LDB.cpp - LDB Support: Declare required global variables --------===//

#include "llvm/Transforms/Utils/LDB.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/MD5.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

// Declare thread-local global variable for LDB
bool llvm::insertLDBGlobals(Module &M) {
  // declare global variables only for module containing main function
  if (!M.getFunction("main"))
    return false;

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

namespace {
// Legacy pass with -enable-new-pm=0
class LDBTLSLegacyPass : public ModulePass {
public:
  // Pass identification
  static char ID;

  // for debug output
  StringRef getPassName() const override {return "LDB TLS"; }

  explicit LDBTLSLegacyPass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {return insertLDBGlobals(M); }
};
char LDBTLSLegacyPass::ID = 0;

} // anonymous namespace

// This is for new PassManager for clang/clang++
PreservedAnalyses LDBTLSPass::run(Module &M,
				  ModuleAnalysisManager &AM) {
  if (!insertLDBGlobals(M))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}

INITIALIZE_PASS_BEGIN(LDBTLSLegacyPass, "ldb-tls-globals",
		      "insert thread-local global variables for LDB",
		      false, false)
INITIALIZE_PASS_END(LDBTLSLegacyPass, "ldb-tls-globals",
		    "insert thread-local global variables for LDB",
		    false, false)

namespace llvm {
ModulePass *createLDBTLSPass() {
  return new LDBTLSLegacyPass();
}
}
