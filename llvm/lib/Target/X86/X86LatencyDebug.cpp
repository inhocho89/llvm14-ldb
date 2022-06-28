#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"
#include "X86MachineFunctionInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/MC/MCContext.h"

using namespace llvm;

#define X86_LDB_STACK_PASS_NAME "X86 Latency Debugger Stack Pass"
#define LDB_STACK_SIZE 16

namespace {
class X86LDBStack : public MachineFunctionPass {
public:
  static char ID;
  const X86Subtarget *STI = nullptr;
  const X86InstrInfo *TII = nullptr;
  const X86RegisterInfo *TRI = nullptr;

  X86LDBStack() : MachineFunctionPass(ID) {
    initializeX86LDBStackPass(*PassRegistry::getPassRegistry());
  }

  bool hasFP(const MachineFunction &MF) const;
  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override { return X86_LDB_STACK_PASS_NAME; }
};

char X86LDBStack::ID = 0;

bool X86LDBStack::hasFP(const MachineFunction &MF) const {
  const MachineFrameInfo &MFI = MF.getFrameInfo();
  return (MF.getTarget().Options.DisableFramePointerElim(MF) ||
          TRI->hasStackRealignment(MF) || MFI.hasVarSizedObjects() ||
          MFI.isFrameAddressTaken() || MFI.hasOpaqueSPAdjustment() ||
          MF.getInfo<X86MachineFunctionInfo>()->getForceFramePointer() ||
          MF.getInfo<X86MachineFunctionInfo>()->hasPreallocatedCall() ||
          MF.callsUnwindInit() || MF.hasEHFunclets() || MF.callsEHReturn() ||
          MFI.hasStackMap() || MFI.hasPatchPoint());
}

bool X86LDBStack::runOnMachineFunction(MachineFunction &MF) {
  STI = &static_cast<const X86Subtarget &>(MF.getSubtarget());
  TII = STI->getInstrInfo();
  TRI = STI->getRegisterInfo();
  MachineFrameInfo &MFI = MF.getFrameInfo();
  MachineRegisterInfo &MRI = MF.getRegInfo();

  if (!hasFP(MF)) {
    return false;
  }

//  MFI.CreateFixedSpillStackObject(LDB_STACK_SIZE, -16-LDB_STACK_SIZE);
  MFI.CreateFixedObject(LDB_STACK_SIZE, -16-LDB_STACK_SIZE, false);

  // Cleaning stack
  MachineBasicBlock* bb0 = &MF.front();
  MachineBasicBlock* bb1 = MF.CreateMachineBasicBlock();

  MF.push_front(bb1);
  bb1->addSuccessor(bb0);

  // initialize reserved space
/*
  // movq $0, -8(%rbp)
  BuildMI(*bb1, bb1->end(), DebugLoc(), TII->get(X86::MOV64mi32))
    .addReg(X86::RBP).addImm(0)
    .addReg(0).addImm(-8)
    .addReg(0).addImm(0);

  // movq $0, -16(%rbp)
  BuildMI(*bb1, bb1->end(), DebugLoc(), TII->get(X86::MOV64mi32))
    .addReg(X86::RBP).addImm(0)
    .addReg(0).addImm(-16)
    .addReg(0).addImm(0);
*/
  // Get a virtual register for memcpy
  Register RegTmp1 = MRI.createVirtualRegister(&X86::GR64RegClass);
  Register RegTmp2 = MRI.createVirtualRegister(&X86::GR64RegClass);

  // incq %fs:__ldb_ngen@TPOFF
  BuildMI(*bb1, bb1->end(), DebugLoc(), TII->get(X86::INC64m))
    .addReg(0).addImm(1)
    .addReg(0).addSym(MF.getContext().getOrCreateSymbol("__ldb_ngen@TPOFF"))
    .addReg(X86::FS);

  // movq %fs:__ldb_ngen@TPOFF, %rx1
  BuildMI(*bb1, bb1->end(), DebugLoc(), TII->get(X86::MOV64rm))
    .addDef(RegTmp1)
    .addReg(0).addImm(1)
    .addReg(0).addSym(MF.getContext().getOrCreateSymbol("__ldb_ngen@TPOFF"))
    .addReg(X86::FS);

  // movq %rx1, -8(%rbp)
  BuildMI(*bb1, bb1->end(), DebugLoc(), TII->get(X86::MOV64mr))
    .addReg(X86::RBP).addImm(1)
    .addReg(0).addImm(-8)
    .addReg(0).addDef(RegTmp1);

  /// update ldb_rbp
  // movq %rbp, %fs:__ldb_rbp@TPOFF
  BuildMI(*bb1, bb1->end(), DebugLoc(), TII->get(X86::MOV64mr))
    .addReg(0).addImm(1)
    .addReg(0).addSym(MF.getContext().getOrCreateSymbol("__ldb_rbp@TPOFF"))
    .addReg(X86::FS)
    .addReg(X86::RBP);

  for (MachineBasicBlock &bb : MF) {
    MachineBasicBlock::iterator i, ie;

    for (i = bb.begin(), ie = bb.end(); i != ie; ++i) {
      MachineInstr *mi = &(*i);

      if (mi->isReturn()) {
        // movq (%rbp), %rx2
        BuildMI(bb, i, DebugLoc(), TII->get(X86::MOV64rm))
          .addDef(RegTmp2)
	  .addReg(X86::RBP).addImm(1)
	  .addReg(0).addImm(0)
	  .addReg(0);

	// movq %rx2, %fs:__ldb_rbp@TPOFF
	BuildMI(bb, i, DebugLoc(), TII->get(X86::MOV64mr))
          .addReg(0).addImm(1)
	  .addReg(0).addSym(MF.getContext().getOrCreateSymbol("__ldb_rbp@TPOFF"))
	  .addReg(X86::FS)
	  .addDef(RegTmp2);
      }
    }
  }

  return true;
}

} // namespace

INITIALIZE_PASS(X86LDBStack, "x86-ldb-stack",
    X86_LDB_STACK_PASS_NAME, false, false)

namespace llvm {
FunctionPass *createX86LDBStack() { return new X86LDBStack(); }
}
