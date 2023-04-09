//===- LDB.cpp - LDB Support: Declare required global variables --------===//

#include "llvm/Transforms/Utils/LDB.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/MD5.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

// Declare thread-local global variable for LDB
bool llvm::insertLDBGlobals(Module &M) {
  if (!M.getFunction("main"))
    return false;

  // allocate tls (400 bytes = 8 bytes * 50)
  // for safety let's reserve 25 byte

  // offset           contents
  // -400       [padding]
  // -352       [padding]
  // -344       [generation number (8 bytes)]
  // -336       [padding]
  //  ...       [padding]
  // -288       [padding]
  // -280       [most recent RBP (8 bytes)]
  // -272       [padding]
  //  ...       [padding]
  // -224       [padding]
  // -216       [canary (8 bytes)]
  // -208       [thread local index (8 bytes)]
  // -200       [Reserved for safety]
  //  ...       [Reserved for safety]
  //   -8       [Reserved for safety]

  Type *ArrTy = ArrayType::get(Type::getInt64Ty(M.getContext()), 50);
  M.getOrInsertGlobal("__ldb_reserved", ArrTy, [&] {
    GlobalVariable *g =
      new GlobalVariable(M, ArrTy, false, GlobalVariable::ExternalLinkage,
       nullptr, "__ldb_reserved", nullptr,
       GlobalVariable::GeneralDynamicTLSModel);
      g->setInitializer(Constant::getNullValue(ArrTy));
      g->setDSOLocal(true);
      g->setAlignment(llvm::Align(8));
      return g;
  });

  // Instrument main function
  // setup hooks
  auto &Context = M.getContext();
  Type* voidTy = Type::getVoidTy(Context);
  FunctionType* funcTy = FunctionType::get(voidTy, false);
  Function::Create(funcTy, llvm::GlobalVariable::ExternalLinkage)->setName("__ldbInit");
  Function::Create(funcTy, llvm::GlobalVariable::ExternalLinkage)->setName("__ldbExit");

  // Loop through all of the functions in the module
  Module::FunctionListType &functions = M.getFunctionList();
  for(Module::FunctionListType::iterator FI = functions.begin(), FE = functions.end();
      FI != FE; ++FI) {
    // Ignore the instrumented function
    if (FI->getName() == "__ldbInit" || FI->getName() == "__ldbExit")
      continue;

    // Instrument main function
    if (FI->getName() == "main") {
      FunctionCallee hook_init = M.getOrInsertFunction("__ldbInit", funcTy);
      FunctionCallee hook_exit = M.getOrInsertFunction("__ldbExit", funcTy);

      // instrument init function
      BasicBlock *BB = &(*FI).front();
      Instruction *I = &BB->front();

      CallInst::Create(hook_init)->insertBefore(I);

      // instrument exit function
      for (BasicBlock &bb : *FI) {
        for (Instruction &i : bb) {
          if (i.getOpcode() == Instruction::Ret) {
            CallInst::Create(hook_exit)->insertBefore(&i);
          }
        }
      }

    }
  }

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
