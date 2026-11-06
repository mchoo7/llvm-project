//===-- RegisterContextWindows_x64.cpp ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__x86_64__) || defined(_M_X64)

#include "lldb/Host/windows/HostThreadWindows.h"
#include "lldb/Host/windows/windows.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"
#include "lldb/lldb-private-types.h"

#include "ProcessWindowsLog.h"
#include "RegisterContextWindows_x64.h"
#include "RegisterModelWindows_x86.h"
#include "TargetThreadWindows.h"
#include "lldb/Register/Arch/lldb-x86-register-enums.h"

using namespace lldb;
using namespace lldb_private;

namespace {
const RegisterInfo_x86 &RegisterMetadata() {
  static const ArchSpec arch("x86_64-pc-windows");
  static const RegisterInfo_x86 info(
      arch, CreateWindowsX86RegisterModel(arch, X86RegisterMode::X86_64,
                                          WindowsX86ContextKind::Frame));
  return info;
}
} // namespace

// Constructors and Destructors
RegisterContextWindows_x64::RegisterContextWindows_x64(
    Thread &thread, uint32_t concrete_frame_idx)
    : RegisterContextWindows(thread, concrete_frame_idx) {}

RegisterContextWindows_x64::~RegisterContextWindows_x64() {}

size_t RegisterContextWindows_x64::GetRegisterCount() {
  return RegisterMetadata().GetRegisterCount();
}

const RegisterInfo *
RegisterContextWindows_x64::GetRegisterInfoAtIndex(size_t reg) {
  const auto &info = RegisterMetadata();
  return reg < info.GetRegisterCount() ? info.GetRegisterInfo() + reg : nullptr;
}

size_t RegisterContextWindows_x64::GetRegisterSetCount() {
  return RegisterMetadata().GetRegisterSetCount();
}

const RegisterSet *RegisterContextWindows_x64::GetRegisterSet(size_t reg_set) {
  return RegisterMetadata().GetRegisterSet(reg_set);
}

bool RegisterContextWindows_x64::ReadRegister(const RegisterInfo *reg_info,
                                              RegisterValue &reg_value) {
  if (!CacheAllRegisterValues())
    return false;

  if (reg_info == nullptr)
    return false;

  const uint32_t reg = reg_info->kinds[eRegisterKindLLDB];

  switch (reg) {
#define GPR_CASE(size, reg_case, reg_val)                                      \
  case reg_case:                                                               \
    reg_value.SetUInt##size(reg_val);                                        \
    break;

  GPR_CASE(64, lldb_rax_x86_64, m_context.Rax);
  GPR_CASE(64, lldb_rbx_x86_64, m_context.Rbx);
  GPR_CASE(64, lldb_rcx_x86_64, m_context.Rcx);
  GPR_CASE(64, lldb_rdx_x86_64, m_context.Rdx);
  GPR_CASE(64, lldb_rdi_x86_64, m_context.Rdi);
  GPR_CASE(64, lldb_rsi_x86_64, m_context.Rsi);
  GPR_CASE(64, lldb_r8_x86_64, m_context.R8);
  GPR_CASE(64, lldb_r9_x86_64, m_context.R9);
  GPR_CASE(64, lldb_r10_x86_64, m_context.R10);
  GPR_CASE(64, lldb_r11_x86_64, m_context.R11);
  GPR_CASE(64, lldb_r12_x86_64, m_context.R12);
  GPR_CASE(64, lldb_r13_x86_64, m_context.R13);
  GPR_CASE(64, lldb_r14_x86_64, m_context.R14);
  GPR_CASE(64, lldb_r15_x86_64, m_context.R15);
  GPR_CASE(64, lldb_rbp_x86_64, m_context.Rbp);
  GPR_CASE(64, lldb_rsp_x86_64, m_context.Rsp);
  GPR_CASE(64, lldb_rip_x86_64, m_context.Rip);
  GPR_CASE(64, lldb_rflags_x86_64, m_context.EFlags);
  GPR_CASE(32, lldb_eax_x86_64, static_cast<uint32_t>(m_context.Rax));
  GPR_CASE(32, lldb_ebx_x86_64, static_cast<uint32_t>(m_context.Rbx));
  GPR_CASE(32, lldb_ecx_x86_64, static_cast<uint32_t>(m_context.Rcx));
  GPR_CASE(32, lldb_edx_x86_64, static_cast<uint32_t>(m_context.Rdx));
  GPR_CASE(32, lldb_edi_x86_64, static_cast<uint32_t>(m_context.Rdi));
  GPR_CASE(32, lldb_esi_x86_64, static_cast<uint32_t>(m_context.Rsi));
  GPR_CASE(32, lldb_ebp_x86_64, static_cast<uint32_t>(m_context.Rbp));
  GPR_CASE(32, lldb_esp_x86_64, static_cast<uint32_t>(m_context.Rsp));
  GPR_CASE(32, lldb_r8d_x86_64, static_cast<uint32_t>(m_context.R8));
  GPR_CASE(32, lldb_r9d_x86_64, static_cast<uint32_t>(m_context.R9));
  GPR_CASE(32, lldb_r10d_x86_64, static_cast<uint32_t>(m_context.R10));
  GPR_CASE(32, lldb_r11d_x86_64, static_cast<uint32_t>(m_context.R11));
  GPR_CASE(32, lldb_r12d_x86_64, static_cast<uint32_t>(m_context.R12));
  GPR_CASE(32, lldb_r13d_x86_64, static_cast<uint32_t>(m_context.R13));
  GPR_CASE(32, lldb_r14d_x86_64, static_cast<uint32_t>(m_context.R14));
  GPR_CASE(32, lldb_r15d_x86_64, static_cast<uint32_t>(m_context.R15));
  GPR_CASE(16, lldb_ax_x86_64, static_cast<uint16_t>(m_context.Rax));
  GPR_CASE(16, lldb_bx_x86_64, static_cast<uint16_t>(m_context.Rbx));
  GPR_CASE(16, lldb_cx_x86_64, static_cast<uint16_t>(m_context.Rcx));
  GPR_CASE(16, lldb_dx_x86_64, static_cast<uint16_t>(m_context.Rdx));
  GPR_CASE(16, lldb_di_x86_64, static_cast<uint16_t>(m_context.Rdi));
  GPR_CASE(16, lldb_si_x86_64, static_cast<uint16_t>(m_context.Rsi));
  GPR_CASE(16, lldb_bp_x86_64, static_cast<uint16_t>(m_context.Rbp));
  GPR_CASE(16, lldb_sp_x86_64, static_cast<uint16_t>(m_context.Rsp));
  GPR_CASE(16, lldb_r8w_x86_64, static_cast<uint16_t>(m_context.R8));
  GPR_CASE(16, lldb_r9w_x86_64, static_cast<uint16_t>(m_context.R9));
  GPR_CASE(16, lldb_r10w_x86_64, static_cast<uint16_t>(m_context.R10));
  GPR_CASE(16, lldb_r11w_x86_64, static_cast<uint16_t>(m_context.R11));
  GPR_CASE(16, lldb_r12w_x86_64, static_cast<uint16_t>(m_context.R12));
  GPR_CASE(16, lldb_r13w_x86_64, static_cast<uint16_t>(m_context.R13));
  GPR_CASE(16, lldb_r14w_x86_64, static_cast<uint16_t>(m_context.R14));
  GPR_CASE(16, lldb_r15w_x86_64, static_cast<uint16_t>(m_context.R15));
  GPR_CASE(8, lldb_ah_x86_64, static_cast<uint16_t>(m_context.Rax) >> 8);
  GPR_CASE(8, lldb_bh_x86_64, static_cast<uint16_t>(m_context.Rbx) >> 8);
  GPR_CASE(8, lldb_ch_x86_64, static_cast<uint16_t>(m_context.Rcx) >> 8);
  GPR_CASE(8, lldb_dh_x86_64, static_cast<uint16_t>(m_context.Rdx) >> 8);
  GPR_CASE(8, lldb_al_x86_64, static_cast<uint8_t>(m_context.Rax));
  GPR_CASE(8, lldb_bl_x86_64, static_cast<uint8_t>(m_context.Rbx));
  GPR_CASE(8, lldb_cl_x86_64, static_cast<uint8_t>(m_context.Rcx));
  GPR_CASE(8, lldb_dl_x86_64, static_cast<uint8_t>(m_context.Rdx));
  GPR_CASE(8, lldb_dil_x86_64, static_cast<uint8_t>(m_context.Rdi));
  GPR_CASE(8, lldb_sil_x86_64, static_cast<uint8_t>(m_context.Rsi));
  GPR_CASE(8, lldb_bpl_x86_64, static_cast<uint8_t>(m_context.Rbp));
  GPR_CASE(8, lldb_spl_x86_64, static_cast<uint8_t>(m_context.Rsp));
  GPR_CASE(8, lldb_r8l_x86_64, static_cast<uint8_t>(m_context.R8));
  GPR_CASE(8, lldb_r9l_x86_64, static_cast<uint8_t>(m_context.R9));
  GPR_CASE(8, lldb_r10l_x86_64, static_cast<uint8_t>(m_context.R10));
  GPR_CASE(8, lldb_r11l_x86_64, static_cast<uint8_t>(m_context.R11));
  GPR_CASE(8, lldb_r12l_x86_64, static_cast<uint8_t>(m_context.R12));
  GPR_CASE(8, lldb_r13l_x86_64, static_cast<uint8_t>(m_context.R13));
  GPR_CASE(8, lldb_r14l_x86_64, static_cast<uint8_t>(m_context.R14));
  GPR_CASE(8, lldb_r15l_x86_64, static_cast<uint8_t>(m_context.R15));

  case lldb_xmm0_x86_64:
    reg_value.SetBytes(&m_context.Xmm0,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm1_x86_64:
    reg_value.SetBytes(&m_context.Xmm1,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm2_x86_64:
    reg_value.SetBytes(&m_context.Xmm2,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm3_x86_64:
    reg_value.SetBytes(&m_context.Xmm3,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm4_x86_64:
    reg_value.SetBytes(&m_context.Xmm4,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm5_x86_64:
    reg_value.SetBytes(&m_context.Xmm5,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm6_x86_64:
    reg_value.SetBytes(&m_context.Xmm6,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm7_x86_64:
    reg_value.SetBytes(&m_context.Xmm7,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm8_x86_64:
    reg_value.SetBytes(&m_context.Xmm8,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm9_x86_64:
    reg_value.SetBytes(&m_context.Xmm9,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm10_x86_64:
    reg_value.SetBytes(&m_context.Xmm10,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm11_x86_64:
    reg_value.SetBytes(&m_context.Xmm11,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm12_x86_64:
    reg_value.SetBytes(&m_context.Xmm12,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm13_x86_64:
    reg_value.SetBytes(&m_context.Xmm13,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm14_x86_64:
    reg_value.SetBytes(&m_context.Xmm14,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  case lldb_xmm15_x86_64:
    reg_value.SetBytes(&m_context.Xmm15,
                       reg_info->byte_size, endian::InlHostByteOrder());
    break;
  }
  return true;
}

bool RegisterContextWindows_x64::WriteRegister(const RegisterInfo *reg_info,
                                               const RegisterValue &reg_value) {
  // Since we cannot only write a single register value to the inferior, we
  // need to make sure our cached copy of the register values are fresh.
  // Otherwise when writing EAX, for example, we may also overwrite some other
  // register with a stale value.
  if (!CacheAllRegisterValues())
    return false;

  const uint32_t reg = reg_info->kinds[eRegisterKindLLDB];

  Log *log = GetLog(WindowsLog::Registers);
  switch (reg) {
  case lldb_rax_x86_64:
    m_context.Rax = reg_value.GetAsUInt64();
    break;
  case lldb_rbx_x86_64:
    m_context.Rbx = reg_value.GetAsUInt64();
    break;
  case lldb_rcx_x86_64:
    m_context.Rcx = reg_value.GetAsUInt64();
    break;
  case lldb_rdx_x86_64:
    m_context.Rdx = reg_value.GetAsUInt64();
    break;
  case lldb_rdi_x86_64:
    m_context.Rdi = reg_value.GetAsUInt64();
    break;
  case lldb_rsi_x86_64:
    m_context.Rsi = reg_value.GetAsUInt64();
    break;
  case lldb_r8_x86_64:
    m_context.R8 = reg_value.GetAsUInt64();
    break;
  case lldb_r9_x86_64:
    m_context.R9 = reg_value.GetAsUInt64();
    break;
  case lldb_r10_x86_64:
    m_context.R10 = reg_value.GetAsUInt64();
    break;
  case lldb_r11_x86_64:
    m_context.R11 = reg_value.GetAsUInt64();
    break;
  case lldb_r12_x86_64:
    m_context.R12 = reg_value.GetAsUInt64();
    break;
  case lldb_r13_x86_64:
    m_context.R13 = reg_value.GetAsUInt64();
    break;
  case lldb_r14_x86_64:
    m_context.R14 = reg_value.GetAsUInt64();
    break;
  case lldb_r15_x86_64:
    m_context.R15 = reg_value.GetAsUInt64();
    break;
  case lldb_rbp_x86_64:
    m_context.Rbp = reg_value.GetAsUInt64();
    break;
  case lldb_rsp_x86_64:
    m_context.Rsp = reg_value.GetAsUInt64();
    break;
  case lldb_rip_x86_64:
    m_context.Rip = reg_value.GetAsUInt64();
    break;
  case lldb_rflags_x86_64:
    m_context.EFlags = reg_value.GetAsUInt64();
    break;
  case lldb_xmm0_x86_64:
    memcpy(&m_context.Xmm0, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm1_x86_64:
    memcpy(&m_context.Xmm1, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm2_x86_64:
    memcpy(&m_context.Xmm2, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm3_x86_64:
    memcpy(&m_context.Xmm3, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm4_x86_64:
    memcpy(&m_context.Xmm4, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm5_x86_64:
    memcpy(&m_context.Xmm5, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm6_x86_64:
    memcpy(&m_context.Xmm6, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm7_x86_64:
    memcpy(&m_context.Xmm7, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm8_x86_64:
    memcpy(&m_context.Xmm8, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm9_x86_64:
    memcpy(&m_context.Xmm9, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm10_x86_64:
    memcpy(&m_context.Xmm10, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm11_x86_64:
    memcpy(&m_context.Xmm11, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm12_x86_64:
    memcpy(&m_context.Xmm12, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm13_x86_64:
    memcpy(&m_context.Xmm13, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm14_x86_64:
    memcpy(&m_context.Xmm14, reg_value.GetBytes(), 16);
    break;
  case lldb_xmm15_x86_64:
    memcpy(&m_context.Xmm15, reg_value.GetBytes(), 16);
    break;
  default:
    LLDB_LOG(log, "Write value {0:x} to unknown register {1}",
             reg_value.GetAsUInt32(), reg);
    return false;
  }

  // Physically update the registers in the target process.
  return ApplyAllRegisterValues();
}

#endif // defined(__x86_64__) || defined(_M_X64)
