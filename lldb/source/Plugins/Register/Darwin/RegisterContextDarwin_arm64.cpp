//===-- RegisterContextDarwin_arm64.cpp -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextDarwin_arm64.h"

#include "lldb/Register/Arch/lldb-arm64-register-enums.h"
#include "lldb/Register/Arch/lldb-arm64-dwarf-eframe-register-enums.h"
#include "lldb/lldb-defines.h"
#include "lldb/lldb-enumerations.h"
#include "lldb/lldb-private-types.h"
#include "lldb/lldb-private.h"
#include <cstddef>
#include <cstdint>

#include "RegisterContextDarwinConstants.h"

#include "lldb/Target/Process.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Endian.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Scalar.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Compiler.h"

#include "Plugins/Process/Utility/InstructionUtils.h"

#include <memory>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#include "lldb/Register/Arch/lldb-arm64-dwarf-eframe-register-enums.h"

using namespace lldb;
using namespace lldb_private;

#define GPR_OFFSET(idx) ((idx)*8)
#define GPR_OFFSET_NAME(reg)                                                   \
  (LLVM_EXTENSION offsetof(RegisterContextDarwin_arm64::GPR, reg))

#define FPU_OFFSET(idx) ((idx)*16 + sizeof(RegisterContextDarwin_arm64::GPR))
#define FPU_OFFSET_NAME(reg)                                                   \
  (LLVM_EXTENSION offsetof(RegisterContextDarwin_arm64::FPU, reg))

#define EXC_OFFSET_NAME(reg)                                                   \
  (LLVM_EXTENSION offsetof(RegisterContextDarwin_arm64::EXC, reg) +            \
   sizeof(RegisterContextDarwin_arm64::GPR) +                                  \
   sizeof(RegisterContextDarwin_arm64::FPU))
#define DBG_OFFSET_NAME(reg)                                                   \
  (LLVM_EXTENSION offsetof(RegisterContextDarwin_arm64::DBG, reg) +            \
   sizeof(RegisterContextDarwin_arm64::GPR) +                                  \
   sizeof(RegisterContextDarwin_arm64::FPU) +                                  \
   sizeof(RegisterContextDarwin_arm64::EXC))

#define DEFINE_DBG(reg, i)                                                     \
  #reg, NULL,                                                                  \
      sizeof(((RegisterContextDarwin_arm64::DBG *) NULL)->reg[i]),             \
              DBG_OFFSET_NAME(reg[i]), eEncodingUint, eFormatHex,              \
                              {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,       \
                               LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,       \
                               LLDB_INVALID_REGNUM },                          \
                               NULL, NULL, NULL
#define REG_CONTEXT_SIZE                                                       \
  (sizeof(RegisterContextDarwin_arm64::GPR) +                                  \
   sizeof(RegisterContextDarwin_arm64::FPU) +                                  \
   sizeof(RegisterContextDarwin_arm64::EXC))

// Include RegisterInfos_arm64 to declare our g_register_infos_arm64 structure.
#define DECLARE_REGISTER_INFOS_ARM64_STRUCT
#include "Register/Arch/RegisterInfos_arm64.h"
#undef DECLARE_REGISTER_INFOS_ARM64_STRUCT

// General purpose registers
static uint32_t g_gpr_regnums[] = {
    gpr_x0_arm64,  gpr_x1_arm64,  gpr_x2_arm64,  gpr_x3_arm64,  gpr_x4_arm64,  gpr_x5_arm64,  gpr_x6_arm64,
    gpr_x7_arm64,  gpr_x8_arm64,  gpr_x9_arm64,  gpr_x10_arm64, gpr_x11_arm64, gpr_x12_arm64, gpr_x13_arm64,
    gpr_x14_arm64, gpr_x15_arm64, gpr_x16_arm64, gpr_x17_arm64, gpr_x18_arm64, gpr_x19_arm64, gpr_x20_arm64,
    gpr_x21_arm64, gpr_x22_arm64, gpr_x23_arm64, gpr_x24_arm64, gpr_x25_arm64, gpr_x26_arm64, gpr_x27_arm64,
    gpr_x28_arm64, gpr_fp_arm64,  gpr_lr_arm64,  gpr_sp_arm64,  gpr_pc_arm64,  gpr_cpsr_arm64};

// Floating point registers
static uint32_t g_fpu_regnums[] = {
    fpu_v0_arm64,  fpu_v1_arm64,  fpu_v2_arm64,  fpu_v3_arm64,  fpu_v4_arm64,   fpu_v5_arm64,  fpu_v6_arm64,
    fpu_v7_arm64,  fpu_v8_arm64,  fpu_v9_arm64,  fpu_v10_arm64, fpu_v11_arm64,  fpu_v12_arm64, fpu_v13_arm64,
    fpu_v14_arm64, fpu_v15_arm64, fpu_v16_arm64, fpu_v17_arm64, fpu_v18_arm64,  fpu_v19_arm64, fpu_v20_arm64,
    fpu_v21_arm64, fpu_v22_arm64, fpu_v23_arm64, fpu_v24_arm64, fpu_v25_arm64,  fpu_v26_arm64, fpu_v27_arm64,
    fpu_v28_arm64, fpu_v29_arm64, fpu_v30_arm64, fpu_v31_arm64, fpu_fpsr_arm64, fpu_fpcr_arm64};

// Exception registers

static uint32_t g_exc_regnums[] = {exc_far_arm64, exc_esr_arm64, exc_exception_arm64};

static size_t k_num_register_infos = std::size(g_register_infos_arm64_le);

RegisterContextDarwin_arm64::RegisterContextDarwin_arm64(
    Thread &thread, uint32_t concrete_frame_idx)
    : RegisterContext(thread, concrete_frame_idx), gpr(), fpu(), exc(), dbg() {
  uint32_t i;
  for (i = 0; i < kNumErrors; i++) {
    gpr_errs[i] = -1;
    fpu_errs[i] = -1;
    exc_errs[i] = -1;
  }
}

RegisterContextDarwin_arm64::~RegisterContextDarwin_arm64() = default;

void RegisterContextDarwin_arm64::InvalidateAllRegisters() {
  InvalidateAllRegisterStates();
}

size_t RegisterContextDarwin_arm64::GetRegisterCount() {
  assert(k_num_register_infos == k_num_registers_arm64);
  return k_num_registers_arm64;
}

const RegisterInfo *
RegisterContextDarwin_arm64::GetRegisterInfoAtIndex(size_t reg) {
  assert(k_num_register_infos == k_num_registers_arm64);
  if (reg < k_num_registers_arm64)
    return &g_register_infos_arm64_le[reg];
  return nullptr;
}

size_t RegisterContextDarwin_arm64::GetRegisterInfosCount() {
  return k_num_register_infos;
}

const RegisterInfo *RegisterContextDarwin_arm64::GetRegisterInfos() {
  return g_register_infos_arm64_le;
}

// Number of registers in each register set
const size_t k_num_gpr_registers = std::size(g_gpr_regnums);
const size_t k_num_fpu_registers = std::size(g_fpu_regnums);
const size_t k_num_exc_registers = std::size(g_exc_regnums);

// Register set definitions. The first definitions at register set index of
// zero is for all registers, followed by other registers sets. The register
// information for the all register set need not be filled in.
static const RegisterSet g_reg_sets[] = {
    {
        "General Purpose Registers", "gpr", k_num_gpr_registers, g_gpr_regnums,
    },
    {"Floating Point Registers", "fpu", k_num_fpu_registers, g_fpu_regnums},
    {"Exception State Registers", "exc", k_num_exc_registers, g_exc_regnums}};

const size_t k_num_regsets = std::size(g_reg_sets);

size_t RegisterContextDarwin_arm64::GetRegisterSetCount() {
  return k_num_regsets;
}

const RegisterSet *RegisterContextDarwin_arm64::GetRegisterSet(size_t reg_set) {
  if (reg_set < k_num_regsets)
    return &g_reg_sets[reg_set];
  return nullptr;
}

// Register information definitions for arm64
int RegisterContextDarwin_arm64::GetSetForNativeRegNum(int reg) {
  if (reg < fpu_v0_arm64)
    return GPRRegSet;
  else if (reg < exc_far_arm64)
    return FPURegSet;
  else if (reg < k_num_registers_arm64)
    return EXCRegSet;
  return -1;
}

int RegisterContextDarwin_arm64::ReadGPR(bool force) {
  int set = GPRRegSet;
  if (force || !RegisterSetIsCached(set)) {
    SetError(set, Read, DoReadGPR(GetThreadID(), set, gpr));
  }
  return GetError(GPRRegSet, Read);
}

int RegisterContextDarwin_arm64::ReadFPU(bool force) {
  int set = FPURegSet;
  if (force || !RegisterSetIsCached(set)) {
    SetError(set, Read, DoReadFPU(GetThreadID(), set, fpu));
  }
  return GetError(FPURegSet, Read);
}

int RegisterContextDarwin_arm64::ReadEXC(bool force) {
  int set = EXCRegSet;
  if (force || !RegisterSetIsCached(set)) {
    SetError(set, Read, DoReadEXC(GetThreadID(), set, exc));
  }
  return GetError(EXCRegSet, Read);
}

int RegisterContextDarwin_arm64::ReadDBG(bool force) {
  int set = DBGRegSet;
  if (force || !RegisterSetIsCached(set)) {
    SetError(set, Read, DoReadDBG(GetThreadID(), set, dbg));
  }
  return GetError(DBGRegSet, Read);
}

int RegisterContextDarwin_arm64::WriteGPR() {
  int set = GPRRegSet;
  if (!RegisterSetIsCached(set)) {
    SetError(set, Write, -1);
    return KERN_INVALID_ARGUMENT;
  }
  SetError(set, Write, DoWriteGPR(GetThreadID(), set, gpr));
  SetError(set, Read, -1);
  return GetError(GPRRegSet, Write);
}

int RegisterContextDarwin_arm64::WriteFPU() {
  int set = FPURegSet;
  if (!RegisterSetIsCached(set)) {
    SetError(set, Write, -1);
    return KERN_INVALID_ARGUMENT;
  }
  SetError(set, Write, DoWriteFPU(GetThreadID(), set, fpu));
  SetError(set, Read, -1);
  return GetError(FPURegSet, Write);
}

int RegisterContextDarwin_arm64::WriteEXC() {
  int set = EXCRegSet;
  if (!RegisterSetIsCached(set)) {
    SetError(set, Write, -1);
    return KERN_INVALID_ARGUMENT;
  }
  SetError(set, Write, DoWriteEXC(GetThreadID(), set, exc));
  SetError(set, Read, -1);
  return GetError(EXCRegSet, Write);
}

int RegisterContextDarwin_arm64::WriteDBG() {
  int set = DBGRegSet;
  if (!RegisterSetIsCached(set)) {
    SetError(set, Write, -1);
    return KERN_INVALID_ARGUMENT;
  }
  SetError(set, Write, DoWriteDBG(GetThreadID(), set, dbg));
  SetError(set, Read, -1);
  return GetError(DBGRegSet, Write);
}

int RegisterContextDarwin_arm64::ReadRegisterSet(uint32_t set, bool force) {
  switch (set) {
  case GPRRegSet:
    return ReadGPR(force);
  case FPURegSet:
    return ReadFPU(force);
  case EXCRegSet:
    return ReadEXC(force);
  case DBGRegSet:
    return ReadDBG(force);
  default:
    break;
  }
  return KERN_INVALID_ARGUMENT;
}

int RegisterContextDarwin_arm64::WriteRegisterSet(uint32_t set) {
  // Make sure we have a valid context to set.
  if (RegisterSetIsCached(set)) {
    switch (set) {
    case GPRRegSet:
      return WriteGPR();
    case FPURegSet:
      return WriteFPU();
    case EXCRegSet:
      return WriteEXC();
    case DBGRegSet:
      return WriteDBG();
    default:
      break;
    }
  }
  return KERN_INVALID_ARGUMENT;
}

void RegisterContextDarwin_arm64::LogDBGRegisters(Log *log, const DBG &dbg) {
  if (log) {
    for (uint32_t i = 0; i < 16; i++)
      LLDB_LOGF(log,
                "BVR%-2u/BCR%-2u = { 0x%8.8" PRIu64 ", 0x%8.8" PRIu64
                " } WVR%-2u/WCR%-2u "
                "= { 0x%8.8" PRIu64 ", 0x%8.8" PRIu64 " }",
                i, i, dbg.bvr[i], dbg.bcr[i], i, i, dbg.wvr[i], dbg.wcr[i]);
  }
}

bool RegisterContextDarwin_arm64::ReadRegister(const RegisterInfo *reg_info,
                                               RegisterValue &value) {
  const uint32_t reg = reg_info->kinds[eRegisterKindLLDB];
  int set = RegisterContextDarwin_arm64::GetSetForNativeRegNum(reg);

  if (set == -1)
    return false;

  if (ReadRegisterSet(set, false) != KERN_SUCCESS)
    return false;

  switch (reg) {
  case gpr_x0_arm64:
  case gpr_x1_arm64:
  case gpr_x2_arm64:
  case gpr_x3_arm64:
  case gpr_x4_arm64:
  case gpr_x5_arm64:
  case gpr_x6_arm64:
  case gpr_x7_arm64:
  case gpr_x8_arm64:
  case gpr_x9_arm64:
  case gpr_x10_arm64:
  case gpr_x11_arm64:
  case gpr_x12_arm64:
  case gpr_x13_arm64:
  case gpr_x14_arm64:
  case gpr_x15_arm64:
  case gpr_x16_arm64:
  case gpr_x17_arm64:
  case gpr_x18_arm64:
  case gpr_x19_arm64:
  case gpr_x20_arm64:
  case gpr_x21_arm64:
  case gpr_x22_arm64:
  case gpr_x23_arm64:
  case gpr_x24_arm64:
  case gpr_x25_arm64:
  case gpr_x26_arm64:
  case gpr_x27_arm64:
  case gpr_x28_arm64:
    value.SetUInt64(gpr.x[reg - gpr_x0_arm64]);
    break;
  case gpr_fp_arm64:
    value.SetUInt64(gpr.fp);
    break;
  case gpr_sp_arm64:
    value.SetUInt64(gpr.sp);
    break;
  case gpr_lr_arm64:
    value.SetUInt64(gpr.lr);
    break;
  case gpr_pc_arm64:
    value.SetUInt64(gpr.pc);
    break;
  case gpr_cpsr_arm64:
    value.SetUInt64(gpr.cpsr);
    break;

  case gpr_w0_arm64:
  case gpr_w1_arm64:
  case gpr_w2_arm64:
  case gpr_w3_arm64:
  case gpr_w4_arm64:
  case gpr_w5_arm64:
  case gpr_w6_arm64:
  case gpr_w7_arm64:
  case gpr_w8_arm64:
  case gpr_w9_arm64:
  case gpr_w10_arm64:
  case gpr_w11_arm64:
  case gpr_w12_arm64:
  case gpr_w13_arm64:
  case gpr_w14_arm64:
  case gpr_w15_arm64:
  case gpr_w16_arm64:
  case gpr_w17_arm64:
  case gpr_w18_arm64:
  case gpr_w19_arm64:
  case gpr_w20_arm64:
  case gpr_w21_arm64:
  case gpr_w22_arm64:
  case gpr_w23_arm64:
  case gpr_w24_arm64:
  case gpr_w25_arm64:
  case gpr_w26_arm64:
  case gpr_w27_arm64:
  case gpr_w28_arm64: {
    ProcessSP process_sp(m_thread.GetProcess());
    if (process_sp.get()) {
      DataExtractor regdata(&gpr.x[reg - gpr_w0_arm64], 8, process_sp->GetByteOrder(),
                            process_sp->GetAddressByteSize());
      offset_t offset = 0;
      uint64_t retval = regdata.GetMaxU64(&offset, 8);
      uint32_t retval_lower32 = static_cast<uint32_t>(retval & 0xffffffff);
      value.SetUInt32(retval_lower32);
    }
  } break;

  case fpu_v0_arm64:
  case fpu_v1_arm64:
  case fpu_v2_arm64:
  case fpu_v3_arm64:
  case fpu_v4_arm64:
  case fpu_v5_arm64:
  case fpu_v6_arm64:
  case fpu_v7_arm64:
  case fpu_v8_arm64:
  case fpu_v9_arm64:
  case fpu_v10_arm64:
  case fpu_v11_arm64:
  case fpu_v12_arm64:
  case fpu_v13_arm64:
  case fpu_v14_arm64:
  case fpu_v15_arm64:
  case fpu_v16_arm64:
  case fpu_v17_arm64:
  case fpu_v18_arm64:
  case fpu_v19_arm64:
  case fpu_v20_arm64:
  case fpu_v21_arm64:
  case fpu_v22_arm64:
  case fpu_v23_arm64:
  case fpu_v24_arm64:
  case fpu_v25_arm64:
  case fpu_v26_arm64:
  case fpu_v27_arm64:
  case fpu_v28_arm64:
  case fpu_v29_arm64:
  case fpu_v30_arm64:
  case fpu_v31_arm64:
    value.SetBytes(fpu.v[reg - fpu_v0_arm64].bytes, reg_info->byte_size,
                   endian::InlHostByteOrder());
    break;

  case fpu_s0_arm64:
  case fpu_s1_arm64:
  case fpu_s2_arm64:
  case fpu_s3_arm64:
  case fpu_s4_arm64:
  case fpu_s5_arm64:
  case fpu_s6_arm64:
  case fpu_s7_arm64:
  case fpu_s8_arm64:
  case fpu_s9_arm64:
  case fpu_s10_arm64:
  case fpu_s11_arm64:
  case fpu_s12_arm64:
  case fpu_s13_arm64:
  case fpu_s14_arm64:
  case fpu_s15_arm64:
  case fpu_s16_arm64:
  case fpu_s17_arm64:
  case fpu_s18_arm64:
  case fpu_s19_arm64:
  case fpu_s20_arm64:
  case fpu_s21_arm64:
  case fpu_s22_arm64:
  case fpu_s23_arm64:
  case fpu_s24_arm64:
  case fpu_s25_arm64:
  case fpu_s26_arm64:
  case fpu_s27_arm64:
  case fpu_s28_arm64:
  case fpu_s29_arm64:
  case fpu_s30_arm64:
  case fpu_s31_arm64: {
    ProcessSP process_sp(m_thread.GetProcess());
    if (process_sp.get()) {
      DataExtractor regdata(&fpu.v[reg - fpu_s0_arm64], 4, process_sp->GetByteOrder(),
                            process_sp->GetAddressByteSize());
      offset_t offset = 0;
      value.SetFloat(regdata.GetFloat(&offset));
    }
  } break;

  case fpu_d0_arm64:
  case fpu_d1_arm64:
  case fpu_d2_arm64:
  case fpu_d3_arm64:
  case fpu_d4_arm64:
  case fpu_d5_arm64:
  case fpu_d6_arm64:
  case fpu_d7_arm64:
  case fpu_d8_arm64:
  case fpu_d9_arm64:
  case fpu_d10_arm64:
  case fpu_d11_arm64:
  case fpu_d12_arm64:
  case fpu_d13_arm64:
  case fpu_d14_arm64:
  case fpu_d15_arm64:
  case fpu_d16_arm64:
  case fpu_d17_arm64:
  case fpu_d18_arm64:
  case fpu_d19_arm64:
  case fpu_d20_arm64:
  case fpu_d21_arm64:
  case fpu_d22_arm64:
  case fpu_d23_arm64:
  case fpu_d24_arm64:
  case fpu_d25_arm64:
  case fpu_d26_arm64:
  case fpu_d27_arm64:
  case fpu_d28_arm64:
  case fpu_d29_arm64:
  case fpu_d30_arm64:
  case fpu_d31_arm64: {
    ProcessSP process_sp(m_thread.GetProcess());
    if (process_sp.get()) {
      DataExtractor regdata(&fpu.v[reg - fpu_d0_arm64], 8, process_sp->GetByteOrder(),
                            process_sp->GetAddressByteSize());
      offset_t offset = 0;
      value.SetDouble(regdata.GetDouble(&offset));
    }
  } break;

  case fpu_fpsr_arm64:
    value.SetUInt32(fpu.fpsr);
    break;

  case fpu_fpcr_arm64:
    value.SetUInt32(fpu.fpcr);
    break;

  case exc_exception_arm64:
    value.SetUInt32(exc.exception);
    break;
  case exc_esr_arm64:
    value.SetUInt32(exc.esr);
    break;
  case exc_far_arm64:
    value.SetUInt64(exc.far);
    break;

  default:
    value.SetValueToInvalid();
    return false;
  }
  return true;
}

bool RegisterContextDarwin_arm64::WriteRegister(const RegisterInfo *reg_info,
                                                const RegisterValue &value) {
  const uint32_t reg = reg_info->kinds[eRegisterKindLLDB];
  int set = GetSetForNativeRegNum(reg);

  if (set == -1)
    return false;

  if (ReadRegisterSet(set, false) != KERN_SUCCESS)
    return false;

  switch (reg) {
  case gpr_x0_arm64:
  case gpr_x1_arm64:
  case gpr_x2_arm64:
  case gpr_x3_arm64:
  case gpr_x4_arm64:
  case gpr_x5_arm64:
  case gpr_x6_arm64:
  case gpr_x7_arm64:
  case gpr_x8_arm64:
  case gpr_x9_arm64:
  case gpr_x10_arm64:
  case gpr_x11_arm64:
  case gpr_x12_arm64:
  case gpr_x13_arm64:
  case gpr_x14_arm64:
  case gpr_x15_arm64:
  case gpr_x16_arm64:
  case gpr_x17_arm64:
  case gpr_x18_arm64:
  case gpr_x19_arm64:
  case gpr_x20_arm64:
  case gpr_x21_arm64:
  case gpr_x22_arm64:
  case gpr_x23_arm64:
  case gpr_x24_arm64:
  case gpr_x25_arm64:
  case gpr_x26_arm64:
  case gpr_x27_arm64:
  case gpr_x28_arm64:
  case gpr_fp_arm64:
  case gpr_sp_arm64:
  case gpr_lr_arm64:
  case gpr_pc_arm64:
  case gpr_cpsr_arm64:
    gpr.x[reg - gpr_x0_arm64] = value.GetAsUInt64();
    break;

  case fpu_v0_arm64:
  case fpu_v1_arm64:
  case fpu_v2_arm64:
  case fpu_v3_arm64:
  case fpu_v4_arm64:
  case fpu_v5_arm64:
  case fpu_v6_arm64:
  case fpu_v7_arm64:
  case fpu_v8_arm64:
  case fpu_v9_arm64:
  case fpu_v10_arm64:
  case fpu_v11_arm64:
  case fpu_v12_arm64:
  case fpu_v13_arm64:
  case fpu_v14_arm64:
  case fpu_v15_arm64:
  case fpu_v16_arm64:
  case fpu_v17_arm64:
  case fpu_v18_arm64:
  case fpu_v19_arm64:
  case fpu_v20_arm64:
  case fpu_v21_arm64:
  case fpu_v22_arm64:
  case fpu_v23_arm64:
  case fpu_v24_arm64:
  case fpu_v25_arm64:
  case fpu_v26_arm64:
  case fpu_v27_arm64:
  case fpu_v28_arm64:
  case fpu_v29_arm64:
  case fpu_v30_arm64:
  case fpu_v31_arm64:
    ::memcpy(fpu.v[reg - fpu_v0_arm64].bytes, value.GetBytes(),
             value.GetByteSize());
    break;

  case fpu_fpsr_arm64:
    fpu.fpsr = value.GetAsUInt32();
    break;

  case fpu_fpcr_arm64:
    fpu.fpcr = value.GetAsUInt32();
    break;

  case exc_exception_arm64:
    exc.exception = value.GetAsUInt32();
    break;
  case exc_esr_arm64:
    exc.esr = value.GetAsUInt32();
    break;
  case exc_far_arm64:
    exc.far = value.GetAsUInt64();
    break;

  default:
    return false;
  }
  return WriteRegisterSet(set) == KERN_SUCCESS;
}

bool RegisterContextDarwin_arm64::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  data_sp = std::make_shared<DataBufferHeap>(REG_CONTEXT_SIZE, 0);
  if (ReadGPR(false) == KERN_SUCCESS && ReadFPU(false) == KERN_SUCCESS &&
      ReadEXC(false) == KERN_SUCCESS) {
    uint8_t *dst = data_sp->GetBytes();
    ::memcpy(dst, &gpr, sizeof(gpr));
    dst += sizeof(gpr);

    ::memcpy(dst, &fpu, sizeof(fpu));
    dst += sizeof(gpr);

    ::memcpy(dst, &exc, sizeof(exc));
    return true;
  }
  return false;
}

bool RegisterContextDarwin_arm64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  if (data_sp && data_sp->GetByteSize() == REG_CONTEXT_SIZE) {
    const uint8_t *src = data_sp->GetBytes();
    ::memcpy(&gpr, src, sizeof(gpr));
    src += sizeof(gpr);

    ::memcpy(&fpu, src, sizeof(fpu));
    src += sizeof(gpr);

    ::memcpy(&exc, src, sizeof(exc));
    uint32_t success_count = 0;
    if (WriteGPR() == KERN_SUCCESS)
      ++success_count;
    if (WriteFPU() == KERN_SUCCESS)
      ++success_count;
    if (WriteEXC() == KERN_SUCCESS)
      ++success_count;
    return success_count == 3;
  }
  return false;
}

uint32_t RegisterContextDarwin_arm64::ConvertRegisterKindToRegisterNumber(
    RegisterKind kind, uint32_t reg) {
  if (kind == eRegisterKindGeneric) {
    switch (reg) {
    case LLDB_REGNUM_GENERIC_PC:
      return gpr_pc_arm64;
    case LLDB_REGNUM_GENERIC_SP:
      return gpr_sp_arm64;
    case LLDB_REGNUM_GENERIC_FP:
      return gpr_fp_arm64;
    case LLDB_REGNUM_GENERIC_RA:
      return gpr_lr_arm64;
    case LLDB_REGNUM_GENERIC_FLAGS:
      return gpr_cpsr_arm64;
    default:
      break;
    }
  } else if (kind == eRegisterKindDWARF) {
    switch (reg) {
    case arm64_dwarf::x0:
      return gpr_x0_arm64;
    case arm64_dwarf::x1:
      return gpr_x1_arm64;
    case arm64_dwarf::x2:
      return gpr_x2_arm64;
    case arm64_dwarf::x3:
      return gpr_x3_arm64;
    case arm64_dwarf::x4:
      return gpr_x4_arm64;
    case arm64_dwarf::x5:
      return gpr_x5_arm64;
    case arm64_dwarf::x6:
      return gpr_x6_arm64;
    case arm64_dwarf::x7:
      return gpr_x7_arm64;
    case arm64_dwarf::x8:
      return gpr_x8_arm64;
    case arm64_dwarf::x9:
      return gpr_x9_arm64;
    case arm64_dwarf::x10:
      return gpr_x10_arm64;
    case arm64_dwarf::x11:
      return gpr_x11_arm64;
    case arm64_dwarf::x12:
      return gpr_x12_arm64;
    case arm64_dwarf::x13:
      return gpr_x13_arm64;
    case arm64_dwarf::x14:
      return gpr_x14_arm64;
    case arm64_dwarf::x15:
      return gpr_x15_arm64;
    case arm64_dwarf::x16:
      return gpr_x16_arm64;
    case arm64_dwarf::x17:
      return gpr_x17_arm64;
    case arm64_dwarf::x18:
      return gpr_x18_arm64;
    case arm64_dwarf::x19:
      return gpr_x19_arm64;
    case arm64_dwarf::x20:
      return gpr_x20_arm64;
    case arm64_dwarf::x21:
      return gpr_x21_arm64;
    case arm64_dwarf::x22:
      return gpr_x22_arm64;
    case arm64_dwarf::x23:
      return gpr_x23_arm64;
    case arm64_dwarf::x24:
      return gpr_x24_arm64;
    case arm64_dwarf::x25:
      return gpr_x25_arm64;
    case arm64_dwarf::x26:
      return gpr_x26_arm64;
    case arm64_dwarf::x27:
      return gpr_x27_arm64;
    case arm64_dwarf::x28:
      return gpr_x28_arm64;

    case arm64_dwarf::fp:
      return gpr_fp_arm64;
    case arm64_dwarf::sp:
      return gpr_sp_arm64;
    case arm64_dwarf::lr:
      return gpr_lr_arm64;
    case arm64_dwarf::pc:
      return gpr_pc_arm64;

    case arm64_dwarf::v0:
      return fpu_v0_arm64;
    case arm64_dwarf::v1:
      return fpu_v1_arm64;
    case arm64_dwarf::v2:
      return fpu_v2_arm64;
    case arm64_dwarf::v3:
      return fpu_v3_arm64;
    case arm64_dwarf::v4:
      return fpu_v4_arm64;
    case arm64_dwarf::v5:
      return fpu_v5_arm64;
    case arm64_dwarf::v6:
      return fpu_v6_arm64;
    case arm64_dwarf::v7:
      return fpu_v7_arm64;
    case arm64_dwarf::v8:
      return fpu_v8_arm64;
    case arm64_dwarf::v9:
      return fpu_v9_arm64;
    case arm64_dwarf::v10:
      return fpu_v10_arm64;
    case arm64_dwarf::v11:
      return fpu_v11_arm64;
    case arm64_dwarf::v12:
      return fpu_v12_arm64;
    case arm64_dwarf::v13:
      return fpu_v13_arm64;
    case arm64_dwarf::v14:
      return fpu_v14_arm64;
    case arm64_dwarf::v15:
      return fpu_v15_arm64;
    case arm64_dwarf::v16:
      return fpu_v16_arm64;
    case arm64_dwarf::v17:
      return fpu_v17_arm64;
    case arm64_dwarf::v18:
      return fpu_v18_arm64;
    case arm64_dwarf::v19:
      return fpu_v19_arm64;
    case arm64_dwarf::v20:
      return fpu_v20_arm64;
    case arm64_dwarf::v21:
      return fpu_v21_arm64;
    case arm64_dwarf::v22:
      return fpu_v22_arm64;
    case arm64_dwarf::v23:
      return fpu_v23_arm64;
    case arm64_dwarf::v24:
      return fpu_v24_arm64;
    case arm64_dwarf::v25:
      return fpu_v25_arm64;
    case arm64_dwarf::v26:
      return fpu_v26_arm64;
    case arm64_dwarf::v27:
      return fpu_v27_arm64;
    case arm64_dwarf::v28:
      return fpu_v28_arm64;
    case arm64_dwarf::v29:
      return fpu_v29_arm64;
    case arm64_dwarf::v30:
      return fpu_v30_arm64;
    case arm64_dwarf::v31:
      return fpu_v31_arm64;

    default:
      break;
    }
  } else if (kind == eRegisterKindEHFrame) {
    switch (reg) {
    case arm64_dwarf::x0:
      return gpr_x0_arm64;
    case arm64_dwarf::x1:
      return gpr_x1_arm64;
    case arm64_dwarf::x2:
      return gpr_x2_arm64;
    case arm64_dwarf::x3:
      return gpr_x3_arm64;
    case arm64_dwarf::x4:
      return gpr_x4_arm64;
    case arm64_dwarf::x5:
      return gpr_x5_arm64;
    case arm64_dwarf::x6:
      return gpr_x6_arm64;
    case arm64_dwarf::x7:
      return gpr_x7_arm64;
    case arm64_dwarf::x8:
      return gpr_x8_arm64;
    case arm64_dwarf::x9:
      return gpr_x9_arm64;
    case arm64_dwarf::x10:
      return gpr_x10_arm64;
    case arm64_dwarf::x11:
      return gpr_x11_arm64;
    case arm64_dwarf::x12:
      return gpr_x12_arm64;
    case arm64_dwarf::x13:
      return gpr_x13_arm64;
    case arm64_dwarf::x14:
      return gpr_x14_arm64;
    case arm64_dwarf::x15:
      return gpr_x15_arm64;
    case arm64_dwarf::x16:
      return gpr_x16_arm64;
    case arm64_dwarf::x17:
      return gpr_x17_arm64;
    case arm64_dwarf::x18:
      return gpr_x18_arm64;
    case arm64_dwarf::x19:
      return gpr_x19_arm64;
    case arm64_dwarf::x20:
      return gpr_x20_arm64;
    case arm64_dwarf::x21:
      return gpr_x21_arm64;
    case arm64_dwarf::x22:
      return gpr_x22_arm64;
    case arm64_dwarf::x23:
      return gpr_x23_arm64;
    case arm64_dwarf::x24:
      return gpr_x24_arm64;
    case arm64_dwarf::x25:
      return gpr_x25_arm64;
    case arm64_dwarf::x26:
      return gpr_x26_arm64;
    case arm64_dwarf::x27:
      return gpr_x27_arm64;
    case arm64_dwarf::x28:
      return gpr_x28_arm64;
    case arm64_dwarf::fp:
      return gpr_fp_arm64;
    case arm64_dwarf::sp:
      return gpr_sp_arm64;
    case arm64_dwarf::lr:
      return gpr_lr_arm64;
    case arm64_dwarf::pc:
      return gpr_pc_arm64;
    }
  } else if (kind == eRegisterKindLLDB) {
    return reg;
  }
  return LLDB_INVALID_REGNUM;
}

uint32_t RegisterContextDarwin_arm64::NumSupportedHardwareWatchpoints() {
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
  // autodetect how many watchpoints are supported dynamically...
  static uint32_t g_num_supported_hw_watchpoints = UINT32_MAX;
  if (g_num_supported_hw_watchpoints == UINT32_MAX) {
    size_t len;
    uint32_t n = 0;
    len = sizeof(n);
    if (::sysctlbyname("hw.optional.watchpoint", &n, &len, NULL, 0) == 0) {
      g_num_supported_hw_watchpoints = n;
    }
  }
  return g_num_supported_hw_watchpoints;
#else
  // TODO: figure out remote case here!
  return 2;
#endif
}

uint32_t RegisterContextDarwin_arm64::SetHardwareWatchpoint(lldb::addr_t addr,
                                                            size_t size,
                                                            bool read,
                                                            bool write) {
  //    if (log) log->Printf
  //    ("RegisterContextDarwin_arm64::EnableHardwareWatchpoint(addr = %8.8p,
  //    size = %u, read = %u, write = %u)", addr, size, read, write);

  const uint32_t num_hw_watchpoints = NumSupportedHardwareWatchpoints();

  // Can't watch zero bytes
  if (size == 0)
    return LLDB_INVALID_INDEX32;

  // We must watch for either read or write
  if (!read && !write)
    return LLDB_INVALID_INDEX32;

  // Can't watch more than 4 bytes per WVR/WCR pair
  if (size > 4)
    return LLDB_INVALID_INDEX32;

  // We can only watch up to four bytes that follow a 4 byte aligned address
  // per watchpoint register pair. Since we have at most so we can only watch
  // until the next 4 byte boundary and we need to make sure we can properly
  // encode this.
  uint32_t addr_word_offset = addr % 4;
  //    if (log) log->Printf
  //    ("RegisterContextDarwin_arm64::EnableHardwareWatchpoint() -
  //    addr_word_offset = 0x%8.8x", addr_word_offset);

  uint32_t byte_mask = ((1u << size) - 1u) << addr_word_offset;
  //    if (log) log->Printf
  //    ("RegisterContextDarwin_arm64::EnableHardwareWatchpoint() - byte_mask =
  //    0x%8.8x", byte_mask);
  if (byte_mask > 0xfu)
    return LLDB_INVALID_INDEX32;

  // Read the debug state
  int kret = ReadDBG(false);

  if (kret == KERN_SUCCESS) {
    // Check to make sure we have the needed hardware support
    uint32_t i = 0;

    for (i = 0; i < num_hw_watchpoints; ++i) {
      if ((dbg.wcr[i] & WCR_ENABLE) == 0)
        break; // We found an available hw breakpoint slot (in i)
    }

    // See if we found an available hw breakpoint slot above
    if (i < num_hw_watchpoints) {
      // Make the byte_mask into a valid Byte Address Select mask
      uint32_t byte_address_select = byte_mask << 5;
      // Make sure bits 1:0 are clear in our address
      dbg.wvr[i] = addr & ~((lldb::addr_t)3);
      dbg.wcr[i] = byte_address_select |     // Which bytes that follow the IMVA
                                             // that we will watch
                   S_USER |                  // Stop only in user mode
                   (read ? WCR_LOAD : 0) |   // Stop on read access?
                   (write ? WCR_STORE : 0) | // Stop on write access?
                   WCR_ENABLE;               // Enable this watchpoint;

      kret = WriteDBG();
      //            if (log) log->Printf
      //            ("RegisterContextDarwin_arm64::EnableHardwareWatchpoint()
      //            WriteDBG() => 0x%8.8x.", kret);

      if (kret == KERN_SUCCESS)
        return i;
    } else {
      //            if (log) log->Printf
      //            ("RegisterContextDarwin_arm64::EnableHardwareWatchpoint():
      //            All hardware resources (%u) are in use.",
      //            num_hw_watchpoints);
    }
  }
  return LLDB_INVALID_INDEX32;
}

bool RegisterContextDarwin_arm64::ClearHardwareWatchpoint(uint32_t hw_index) {
  int kret = ReadDBG(false);

  const uint32_t num_hw_points = NumSupportedHardwareWatchpoints();
  if (kret == KERN_SUCCESS) {
    if (hw_index < num_hw_points) {
      dbg.wcr[hw_index] = 0;
      //            if (log) log->Printf
      //            ("RegisterContextDarwin_arm64::ClearHardwareWatchpoint( %u )
      //            - WVR%u = 0x%8.8x  WCR%u = 0x%8.8x",
      //                    hw_index,
      //                    hw_index,
      //                    dbg.wvr[hw_index],
      //                    hw_index,
      //                    dbg.wcr[hw_index]);

      kret = WriteDBG();

      if (kret == KERN_SUCCESS)
        return true;
    }
  }
  return false;
}
