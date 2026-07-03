/*
 * StorFuzzPass.cc — StorFuzz data-flow coverage, LLVM 11 Legacy PM port.
 *
 * Original: StorFuzz-LibAFL/libafl_cc/src/storfuzz-coverage-pass.cc
 * Ported to Angora / LLVM-11 Legacy Pass Manager.
 *
 * Key differences vs. LibAFL version:
 *  - Legacy PM only (no USE_NEW_PM)
 *  - isEntryBlock() → pointer comparison (API removed in LLVM 11)
 *  - LoopInfo: obtained via getAnalysis<LoopInfoWrapperPass>(F) per function
 *  - getLatchCmpInst() absent in LLVM 11; reimplemented manually via
 *    getLoopLatch() + BranchInst conditional check (same semantics)
 *  - GlobalValue::ExternalLinkage (not Weak) — weak refs don't force archive
 *    member inclusion, causing NULL-ptr segfault at runtime
 *  - Map ptr named __angora_data_area_ptr (Angora namespace)
 *  - No PseudoProbeInst (LLVM 14+ feature)
 *  - AtomicRMW without MaybeAlign (LLVM 13+ feature)
 *  - CreateLoad without explicit element type (LLVM 14+ required it)
 */

#include "llvm/Pass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/LegacyPassManager.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace llvm;

/* Map size is the single source of truth in common/src/config.rs
 * (DATA_MAP_SIZE_POW2), injected here by CMake as -DDATA_MAP_SIZE_POW2=...
 * Fallback 17 = the minimum the assert below allows for REDUCTION_WIDTH=8. */
#ifndef STORFUZZ_MAP_SIZE_POW2
# ifdef DATA_MAP_SIZE_POW2
#  define STORFUZZ_MAP_SIZE_POW2 DATA_MAP_SIZE_POW2
# else
#  define STORFUZZ_MAP_SIZE_POW2 17
# endif
#endif
#define STORFUZZ_MAP_SIZE (1u << STORFUZZ_MAP_SIZE_POW2)

namespace {

class StorFuzzCoverage : public ModulePass {
 public:
  static char ID;
  StorFuzzCoverage() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<LoopInfoWrapperPass>();
    AU.setPreservesAll();
  }

 protected:
  uint32_t map_size = STORFUZZ_MAP_SIZE;

  /* Find a valid insertion point in the same BB at or after 'start'.
   * Returns true on success, sets insertionPoint. */
  bool getInsertionPointInSameBB(Instruction          *start,
                                 BasicBlock::iterator &insertionPoint) {
    BasicBlock             *insertionBB = start->getParent();
    insertionPoint                      = start->getIterator();
    BasicBlock::const_iterator End      = insertionBB->end();
    int                        i        = 0;

    if (insertionPoint == End) return false;
    ++insertionPoint;
    while (insertionPoint != End && i < (int)insertionBB->size()) {
      if (!isa<PHINode>(*insertionPoint) && !insertionPoint->isEHPad()) {
        return true;
      } else if (insertionBB ==
                 &insertionBB->getParent()->getEntryBlock()) {
        /* Entry block: skip static allocas and debug info. */
        while (insertionPoint != End &&
               i < (int)insertionBB->size() &&
               (isa<AllocaInst>(*insertionPoint) ||
                isa<DbgInfoIntrinsic>(*insertionPoint))) {
          if (const AllocaInst *AI =
                  dyn_cast<AllocaInst>(&*insertionPoint)) {
            if (!AI->isStaticAlloca()) break;
          }
          i++;
          ++insertionPoint;
        }
        return true;
      }
      ++insertionPoint;
      i++;
    }
    if (i >= (int)insertionBB->size()) {
      errs() << "ERROR: StorFuzzPass: exceeded BB size.\n";
      return false;
    }
    return insertionPoint != End;
  }

  bool isIgnoreFunction(const llvm::Function *F) {
    static constexpr const char *ignoreList[] = {
        "asan.",          "llvm.",         "sancov.",
        "__ubsan",        "ign.",          "__afl",
        "_fini",          "__libc_",       "__asan",
        "__msan",         "__cmplog",      "__sancov",
        "__san",          "__cxx_",        "__decide_deferred",
        "_GLOBAL",        "_ZZN6__asan",   "_ZZN6__lsan",
        "msan.",          "LLVMFuzzerM",   "LLVMFuzzerC",
        "LLVMFuzzerI",
    };
    for (auto const &fn : ignoreList)
      if (F->getName().startswith(fn)) return true;

    static constexpr const char *ignoreSubstringList[] = {
        "__asan",    "__msan",     "__ubsan",   "__lsan",
        "__san",     "__sanitize", "__cxx",     "_GLOBAL__",
        "DebugCounter", "DwarfDebug", "DebugLoc",
    };
    for (auto const &fn : ignoreSubstringList)
      if (StringRef::npos != F->getName().find(fn)) return true;

    return false;
  }

  static bool isSmallConstantAddSub(Instruction *instr, uint64_t k = 2) {
    if (instr->getOpcode() == Instruction::Add) {
      for (auto op : instr->operand_values())
        if (isa<ConstantInt>(op) &&
            cast<ConstantInt>(op)->getValue().abs().ule(k))
          return true;
    } else if (instr->getOpcode() == Instruction::Sub) {
      if (isa<ConstantInt>(instr->getOperand(1)) &&
          cast<ConstantInt>(instr->getOperand(1))
              ->getValue()
              .abs()
              .ule(k))
        return true;
    }
    return false;
  }

  Value *uncast(Value *value) {
    while (CastInst *ci = dyn_cast<CastInst>(value))
      value = ci->getOperand(0);
    return value;
  }

  /* getLatchCmpInst() was added in LLVM 12; reimplement it for LLVM 11.
   * The latch block's terminator is a conditional branch whose condition
   * is the loop comparison — identical to the upstream implementation. */
  static CmpInst *getLatchCmpInst(const Loop *loop) {
    BasicBlock *latch = loop->getLoopLatch();
    if (!latch) return nullptr;
    BranchInst *bi = dyn_cast<BranchInst>(latch->getTerminator());
    if (!bi || !bi->isConditional()) return nullptr;
    return dyn_cast<CmpInst>(bi->getCondition());
  }

  bool isLoopCtr(LoopInfo *LI, Value *potentialLoopCtr,
                 Value *potentialLoopCtrLocation) {
    if (!LI) return false;

    Value       *actualDef     = uncast(potentialLoopCtr);
    Instruction *actualDefInst = dyn_cast<Instruction>(actualDef);
    if (!actualDefInst) return false;
    if (!isSmallConstantAddSub(actualDefInst, 8)) return false;

    auto loop = LI->getLoopFor(actualDefInst->getParent());
    while (loop) {
      CmpInst *cmp_instr = getLatchCmpInst(loop);
      if (cmp_instr) {
        for (auto val : cmp_instr->operand_values()) {
          if (val == actualDef || val == potentialLoopCtr ||
              val == potentialLoopCtrLocation)
            return true;
          if (isa<Instruction>(val)) {
            for (auto iv : cast<Instruction>(val)->operand_values())
              if (iv == actualDef || iv == potentialLoopCtr ||
                  iv == potentialLoopCtrLocation)
                return true;
          }
        }
      }
      loop = loop->getParentLoop();
    }
    return false;
  }
};

}  // namespace

char StorFuzzCoverage::ID = 1;

bool StorFuzzCoverage::runOnModule(Module &M) {
  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  srand((uint32_t)time(NULL));

  /* CRITICAL: ExternalLinkage (not ExternalWeakLinkage).
   * Weak references do not force archive member inclusion; the binary
   * would segfault with a null __angora_data_area_ptr. */
  GlobalVariable *StorFuzzMapPtr = new GlobalVariable(
      M, PointerType::getUnqual(Int8Ty), false,
      GlobalValue::ExternalLinkage, nullptr,
      "__angora_data_area_ptr");

  ConstantInt *Mask[8] = {
      ConstantInt::get(Int8Ty, 1 << 0),
      ConstantInt::get(Int8Ty, 1 << 1),
      ConstantInt::get(Int8Ty, 1 << 2),
      ConstantInt::get(Int8Ty, 1 << 3),
      ConstantInt::get(Int8Ty, 1 << 4),
      ConstantInt::get(Int8Ty, 1 << 5),
      ConstantInt::get(Int8Ty, 1 << 6),
      ConstantInt::get(Int8Ty, 1 << 7),
  };

  int THRESHOLD = 9;
  if (const char *env = getenv("MAX_STORES_PER_BB")) THRESHOLD = atoi(env);
  if (THRESHOLD <= 0) THRESHOLD = 9;

  assert(isPowerOf2_32(map_size));

  int REDUCTION_WIDTH = 8;
  if (const char *env = getenv("VALUE_REDUCTION_WIDTH"))
    REDUCTION_WIDTH = atoi(env);
  if (REDUCTION_WIDTH <= 0) REDUCTION_WIDTH = 8;

  assert((uint64_t)map_size * 8 >=
         (uint64_t)(1 << REDUCTION_WIDTH) * 4096);

  int inst_stores = 0;
  int inst_funcs  = 0;

  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    if (isIgnoreFunction(&F)) continue;
    if (F.onlyReadsMemory()) continue;
    if (F.size() == 0) continue;

    LoopInfo *LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();

    SmallDenseMap<BasicBlock *, uint16_t> stores_per_bb(8);

    /* Two-pass: pass 0 counts stores per BB, pass 1 instruments. */
    for (int pass = 0; pass < 2; pass++) {
      bool instrument_this_time = (pass == 1);

      if (instrument_this_time && stores_per_bb.empty()) {
        errs() << "WARNING: StorFuzzPass: no stores found in '"
               << F.getName() << "'\n";
        break;
      }

      for (auto &BB : F) {
        BasicBlock::iterator insertionPoint = BB.getFirstInsertionPt();
        IRBuilder<>          IRB(&(*insertionPoint));
        uint16_t             BB_store_count = 0;

        if (instrument_this_time) {
          auto it              = stores_per_bb.find(&BB);
          int  stores_in_bb   = (it != stores_per_bb.end())
                                    ? (int)it->getSecond()
                                    : 0;
          if (stores_in_bb == 0) continue;
          if (stores_in_bb > THRESHOLD) continue;
        }

        for (auto &instr : BB) {
          StoreInst *storeInst = dyn_cast<StoreInst>(&instr);
          if (!storeInst) continue;
          if (storeInst->getMetadata("nosanitize") != nullptr) continue;

          Value *storeLocation = storeInst->getPointerOperand();
          if (dyn_cast<AllocaInst>(storeLocation)) continue;

          Value       *storedValue         = storeInst->getValueOperand();
          Instruction *valueDefInstruction = dyn_cast<Instruction>(storedValue);
          if (!valueDefInstruction) continue;

          if (!dyn_cast<IntegerType>(storedValue->getType())) continue;

          Value       *actual_storedValue = uncast(storedValue);
          Instruction *actual_valueDef    = dyn_cast<Instruction>(actual_storedValue);
          if (!actual_valueDef) continue;

          if (!getenv("STORFUZZ_INSTRUMENT_MEM2MEM_COPY")) {
            if (isa<LoadInst>(actual_valueDef) ||
                isa<VAArgInst>(actual_valueDef))
              continue;
          }

          if (isLoopCtr(LI, storedValue, storeLocation)) continue;

          if (!dyn_cast<IntegerType>(actual_storedValue->getType())) continue;

          DenseMap<Value *, ConstantInt *> storeLocationToID(4);

          if (!instrument_this_time) {
            /* Count stores for threshold check. */
            if (isa<PHINode>(storeLocation)) {
              PHINode *phi = dyn_cast<PHINode>(storeLocation);
              for (uint32_t i = 0; i < phi->getNumIncomingValues(); i++) {
                Value *incoming = phi->getIncomingValue(i);
                if (storeLocationToID.find(incoming) ==
                    storeLocationToID.end()) {
                  storeLocationToID.insert({incoming, nullptr});
                  BB_store_count++;
                }
              }
            } else {
              BB_store_count++;
            }
          } else {
            /* Instrument. */
            Value    *CurLoc;
            uint32_t  bitmask_selector;

            if (isa<PHINode>(storeLocation)) {
              PHINode *phi = dyn_cast<PHINode>(storeLocation);
              insertionPoint = phi->getIterator();
              while (insertionPoint != phi->getParent()->end() &&
                     isa<PHINode>(*insertionPoint))
                ++insertionPoint;
              assert(insertionPoint != phi->getParent()->end());
              IRB.SetInsertPoint(phi->getParent(), insertionPoint);

              PHINode *CurLocPhi =
                  IRB.CreatePHI(Int32Ty, phi->getNumIncomingValues());
              for (uint32_t i = 0; i < phi->getNumIncomingValues(); i++) {
                Value      *incoming = phi->getIncomingValue(i);
                ConstantInt *curLocID;
                auto         it = storeLocationToID.find(incoming);
                if (it == storeLocationToID.end()) {
                  curLocID =
                      ConstantInt::get(Int32Ty, (uint32_t)rand() % map_size);
                  BB_store_count++;
                  storeLocationToID.insert({incoming, curLocID});
                } else {
                  curLocID = it->getSecond();
                }
                CurLocPhi->addIncoming(curLocID, phi->getIncomingBlock(i));
              }
              CurLoc = CurLocPhi;
            } else {
              CurLoc = ConstantInt::get(Int32Ty, (uint32_t)rand() % map_size);
              BB_store_count++;
            }

            bitmask_selector = (uint32_t)rand() % 8;

            /* Find insertion point near value definition. */
            bool found = false;
            if (!isa<PHINode>(storeLocation))
              found = getInsertionPointInSameBB(valueDefInstruction,
                                                insertionPoint);

            if (!found) {
              if (!isa<PHINode>(storeLocation)) {
                errs() << "WARNING: StorFuzzPass: no insertion point near"
                          " value def in '"
                       << F.getName() << "'\n";
              }
              if (!getInsertionPointInSameBB(storeInst, insertionPoint)) {
                errs() << "ERROR: StorFuzzPass: no insertion point in '"
                       << F.getName() << "'\n";
                continue; /* skip this store */
              }
            }

            BasicBlock *insertionBB = (*insertionPoint).getParent();
            IRB.SetInsertPoint(insertionBB, insertionPoint);

            Value *mask = Mask[bitmask_selector];

            /* Value reduction: integer → 16-bit → XOR halves → 8-bit. */
            Value *Lower16Bit =
                IRB.CreateZExtOrTrunc(storedValue, IRB.getInt16Ty());
            Value *ReducedValue;

            if (REDUCTION_WIDTH == 8) {
              Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                  IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
              Value *Lower8Bit =
                  IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());
              ReducedValue = IRB.CreateXor(Upper8Bit, Lower8Bit);
            } else if (REDUCTION_WIDTH == 4) {
              Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                  IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
              Value *Lower8Bit =
                  IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());
              Value *half = IRB.CreateXor(Upper8Bit, Lower8Bit);
              ReducedValue = IRB.CreateXor(IRB.CreateAnd(half, 0xF),
                                           IRB.CreateLShr(half, 4));
            } else if (REDUCTION_WIDTH == 12) {
              Value *tmp =
                  IRB.CreateLShr(IRB.CreateAnd(Lower16Bit, 0xFF00), 4);
              Value *tmp2 = IRB.CreateAnd(Lower16Bit, 0xFF);
              ReducedValue =
                  IRB.CreateAnd(IRB.CreateXor(tmp, tmp2), 0xFFF);
            } else if (REDUCTION_WIDTH == 16) {
              ReducedValue = Lower16Bit;
            } else {
              errs() << "StorFuzzPass: unsupported REDUCTION_WIDTH="
                     << REDUCTION_WIDTH << "\n";
              continue;
            }

            /* Load the map pointer (LLVM 11: no explicit element type). */
            LoadInst *MapPtrLoad = IRB.CreateLoad(StorFuzzMapPtr);
            MapPtrLoad->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

            /* GEP: map[site_id XOR reduced_value] */
            Value *MapPtrIdx = IRB.CreateGEP(
                MapPtrLoad,
                IRB.CreateXor(CurLoc,
                              IRB.CreateZExtOrTrunc(ReducedValue,
                                                    IRB.getInt32Ty())));
            dyn_cast<Instruction>(MapPtrIdx)->setMetadata(
                M.getMDKindID("storfuzz_calc_index"),
                MDNode::get(C, None));

            if (getenv("STORFUZZ_VERBOSE"))
              errs() << "STORFUZZ: instrumented store in '"
                     << F.getName() << "'\n";

            /* Atomic OR into the data coverage map. */
            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Or,
                                MapPtrIdx, mask,
                                llvm::AtomicOrdering::Monotonic);
          } /* instrument_this_time */
        }   /* instructions */

        if (!instrument_this_time) {
          if (stores_per_bb.count(&BB) != 0)
            errs() << "ERROR: StorFuzzPass: BB already counted\n";
          stores_per_bb.insert({&BB, BB_store_count});
          BB_store_count = 0;
        } else {
          inst_stores += BB_store_count;
        }
      } /* basic blocks */
    }   /* passes */

    if (inst_stores > 0) inst_funcs++;
  } /* functions */

  if (getenv("STORFUZZ_VERBOSE"))
    errs() << "StorFuzzPass: instrumented " << inst_stores
           << " stores in " << inst_funcs << " functions in '"
           << M.getName() << "'\n";

  return true;
}

static void registerStorFuzzPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase  &PM) {
  PM.add(new StorFuzzCoverage());
}

static RegisterStandardPasses RegisterStorFuzzPass(
    PassManagerBuilder::EP_OptimizerLast, registerStorFuzzPass);

static RegisterStandardPasses RegisterStorFuzzPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerStorFuzzPass);
