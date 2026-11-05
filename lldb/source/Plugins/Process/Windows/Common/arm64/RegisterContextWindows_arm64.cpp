//===-- RegisterContextWindows_arm64.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__aarch64__) || defined(_M_ARM64)

#include "lldb/Host/windows/HostThreadWindows.h"

#include "lldb/Register/Arch/lldb-arm64-register-enums.h"
#include "lldb/Register/Arch/lldb-arm64-dwarf-eframe-register-enums.h"
#include "lldb/lldb-defines.h"
#include "lldb/lldb-enumerations.h"
#include "lldb/lldb-private.h"
#include "llvm/Support/Compiler.h"
#include <cstddef>
#include <cstdint>

#include "lldb/Host/windows/windows.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"
#include "lldb/lldb-private-types.h"

#include "RegisterContextWindows_arm64.h"
#include "TargetThreadWindows.h"

#include "llvm/ADT/STLExtras.h"

using namespace lldb;
using namespace lldb_private;

#define GPR_OFFSET(idx) 0
#define GPR_OFFSET_NAME(reg) 0

#define FPU_OFFSET(idx) 0
#define FPU_OFFSET_NAME(reg) 0

#define EXC_OFFSET_NAME(reg) 0
#define DBG_OFFSET_NAME(reg) 0

#define DEFINE_DBG(reg, i)                                                     \
  #reg, nullptr, 0, DBG_OFFSET_NAME(reg[i]), eEncodingUint, eFormatHex,        \
      {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,          \
       LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM},                              \
      nullptr, nullptr, nullptr

// Include RegisterInfos_arm64 to declare our g_register_infos_arm64 structure.
#define DECLARE_REGISTER_INFOS_ARM64_STRUCT
#include "Register/Arch/RegisterInfos_arm64.h"
#undef DECLARE_REGISTER_INFOS_ARM64_STRUCT

static size_t k_num_register_infos = std::size(g_register_infos_arm64_le);

// Array of lldb register numbers used to define the set of all General Purpose
// Registers
uint32_t g_gpr_reg_indices[] = {
    gpr_x0_arm64,  gpr_x1_arm64,   gpr_x2_arm64,  gpr_x3_arm64,  gpr_x4_arm64,  gpr_x5_arm64,  gpr_x6_arm64,  gpr_x7_arm64,
    gpr_x8_arm64,  gpr_x9_arm64,   gpr_x10_arm64, gpr_x11_arm64, gpr_x12_arm64, gpr_x13_arm64, gpr_x14_arm64, gpr_x15_arm64,
    gpr_x16_arm64, gpr_x17_arm64,  gpr_x18_arm64, gpr_x19_arm64, gpr_x20_arm64, gpr_x21_arm64, gpr_x22_arm64, gpr_x23_arm64,
    gpr_x24_arm64, gpr_x25_arm64,  gpr_x26_arm64, gpr_x27_arm64, gpr_x28_arm64, gpr_fp_arm64,  gpr_lr_arm64,  gpr_sp_arm64,
    gpr_pc_arm64,  gpr_cpsr_arm64,

    gpr_w0_arm64,  gpr_w1_arm64,   gpr_w2_arm64,  gpr_w3_arm64,  gpr_w4_arm64,  gpr_w5_arm64,  gpr_w6_arm64,  gpr_w7_arm64,
    gpr_w8_arm64,  gpr_w9_arm64,   gpr_w10_arm64, gpr_w11_arm64, gpr_w12_arm64, gpr_w13_arm64, gpr_w14_arm64, gpr_w15_arm64,
    gpr_w16_arm64, gpr_w17_arm64,  gpr_w18_arm64, gpr_w19_arm64, gpr_w20_arm64, gpr_w21_arm64, gpr_w22_arm64, gpr_w23_arm64,
    gpr_w24_arm64, gpr_w25_arm64,  gpr_w26_arm64, gpr_w27_arm64, gpr_w28_arm64,
};

uint32_t g_fpu_reg_indices[] = {
    fpu_v0_arm64,   fpu_v1_arm64,   fpu_v2_arm64,  fpu_v3_arm64,  fpu_v4_arm64,  fpu_v5_arm64,  fpu_v6_arm64,  fpu_v7_arm64,
    fpu_v8_arm64,   fpu_v9_arm64,   fpu_v10_arm64, fpu_v11_arm64, fpu_v12_arm64, fpu_v13_arm64, fpu_v14_arm64, fpu_v15_arm64,
    fpu_v16_arm64,  fpu_v17_arm64,  fpu_v18_arm64, fpu_v19_arm64, fpu_v20_arm64, fpu_v21_arm64, fpu_v22_arm64, fpu_v23_arm64,
    fpu_v24_arm64,  fpu_v25_arm64,  fpu_v26_arm64, fpu_v27_arm64, fpu_v28_arm64, fpu_v29_arm64, fpu_v30_arm64, fpu_v31_arm64,

    fpu_s0_arm64,   fpu_s1_arm64,   fpu_s2_arm64,  fpu_s3_arm64,  fpu_s4_arm64,  fpu_s5_arm64,  fpu_s6_arm64,  fpu_s7_arm64,
    fpu_s8_arm64,   fpu_s9_arm64,   fpu_s10_arm64, fpu_s11_arm64, fpu_s12_arm64, fpu_s13_arm64, fpu_s14_arm64, fpu_s15_arm64,
    fpu_s16_arm64,  fpu_s17_arm64,  fpu_s18_arm64, fpu_s19_arm64, fpu_s20_arm64, fpu_s21_arm64, fpu_s22_arm64, fpu_s23_arm64,
    fpu_s24_arm64,  fpu_s25_arm64,  fpu_s26_arm64, fpu_s27_arm64, fpu_s28_arm64, fpu_s29_arm64, fpu_s30_arm64, fpu_s31_arm64,

    fpu_d0_arm64,   fpu_d1_arm64,   fpu_d2_arm64,  fpu_d3_arm64,  fpu_d4_arm64,  fpu_d5_arm64,  fpu_d6_arm64,  fpu_d7_arm64,
    fpu_d8_arm64,   fpu_d9_arm64,   fpu_d10_arm64, fpu_d11_arm64, fpu_d12_arm64, fpu_d13_arm64, fpu_d14_arm64, fpu_d15_arm64,
    fpu_d16_arm64,  fpu_d17_arm64,  fpu_d18_arm64, fpu_d19_arm64, fpu_d20_arm64, fpu_d21_arm64, fpu_d22_arm64, fpu_d23_arm64,
    fpu_d24_arm64,  fpu_d25_arm64,  fpu_d26_arm64, fpu_d27_arm64, fpu_d28_arm64, fpu_d29_arm64, fpu_d30_arm64, fpu_d31_arm64,

    fpu_fpsr_arm64, fpu_fpcr_arm64,
};

RegisterSet g_register_sets[] = {
    {"General Purpose Registers", "gpr", std::size(g_gpr_reg_indices),
     g_gpr_reg_indices},
    {"Floating Point Registers", "fpu", std::size(g_fpu_reg_indices),
     g_fpu_reg_indices},
};

// Constructors and Destructors
RegisterContextWindows_arm64::RegisterContextWindows_arm64(
    Thread &thread, uint32_t concrete_frame_idx)
    : RegisterContextWindows(thread, concrete_frame_idx) {}

RegisterContextWindows_arm64::~RegisterContextWindows_arm64() {}

size_t RegisterContextWindows_arm64::GetRegisterCount() {
  return std::size(g_register_infos_arm64_le);
}

const RegisterInfo *
RegisterContextWindows_arm64::GetRegisterInfoAtIndex(size_t reg) {
  if (reg < k_num_register_infos)
    return &g_register_infos_arm64_le[reg];
  return nullptr;
}

size_t RegisterContextWindows_arm64::GetRegisterSetCount() {
  return std::size(g_register_sets);
}

const RegisterSet *
RegisterContextWindows_arm64::GetRegisterSet(size_t reg_set) {
  return &g_register_sets[reg_set];
}

bool RegisterContextWindows_arm64::ReadRegister(const RegisterInfo *reg_info,
                                                RegisterValue &reg_value) {
  if (!CacheAllRegisterValues())
    return false;

  if (reg_info == nullptr)
    return false;

  const uint32_t reg = reg_info->kinds[eRegisterKindLLDB];

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
    reg_value.SetUInt64(m_context.X[reg - gpr_x0_arm64]);
    break;

  case gpr_fp_arm64:
    reg_value.SetUInt64(m_context.Fp);
    break;
  case gpr_sp_arm64:
    reg_value.SetUInt64(m_context.Sp);
    break;
  case gpr_lr_arm64:
    reg_value.SetUInt64(m_context.Lr);
    break;
  case gpr_pc_arm64:
    reg_value.SetUInt64(m_context.Pc);
    break;
  case gpr_cpsr_arm64:
    reg_value.SetUInt32(m_context.Cpsr);
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
  case gpr_w28_arm64:
    reg_value.SetUInt32(
        static_cast<uint32_t>(m_context.X[reg - gpr_w0_arm64] & 0xffffffff));
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
    reg_value.SetBytes(m_context.V[reg - fpu_v0_arm64].B, reg_info->byte_size,
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
  case fpu_s31_arm64:
    reg_value.SetFloat(m_context.V[reg - fpu_s0_arm64].S[0]);
    break;

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
  case fpu_d31_arm64:
    reg_value.SetDouble(m_context.V[reg - fpu_d0_arm64].D[0]);
    break;

  case fpu_fpsr_arm64:
    reg_value.SetUInt32(m_context.Fpsr);
    break;

  case fpu_fpcr_arm64:
    reg_value.SetUInt32(m_context.Fpcr);
    break;

  default:
    reg_value.SetValueToInvalid();
    return false;
  }
  return true;
}

bool RegisterContextWindows_arm64::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  // Since we cannot only write a single register value to the inferior, we
  // need to make sure our cached copy of the register values are fresh.
  // Otherwise when writing one register, we may also overwrite some other
  // register with a stale value.
  if (!CacheAllRegisterValues())
    return false;

  const uint32_t reg = reg_info->kinds[eRegisterKindLLDB];

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
    m_context.X[reg - gpr_x0_arm64] = reg_value.GetAsUInt64();
    break;

  case gpr_fp_arm64:
    m_context.Fp = reg_value.GetAsUInt64();
    break;
  case gpr_sp_arm64:
    m_context.Sp = reg_value.GetAsUInt64();
    break;
  case gpr_lr_arm64:
    m_context.Lr = reg_value.GetAsUInt64();
    break;
  case gpr_pc_arm64:
    m_context.Pc = reg_value.GetAsUInt64();
    break;
  case gpr_cpsr_arm64:
    m_context.Cpsr = reg_value.GetAsUInt32();
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
    memcpy(m_context.V[reg - fpu_v0_arm64].B, reg_value.GetBytes(), 16);
    break;

  case fpu_fpsr_arm64:
    m_context.Fpsr = reg_value.GetAsUInt32();
    break;

  case fpu_fpcr_arm64:
    m_context.Fpcr = reg_value.GetAsUInt32();
    break;

  default:
    return false;
  }

  // Physically update the registers in the target process.
  return ApplyAllRegisterValues();
}

#endif // defined(__aarch64__) || defined(_M_ARM64)
