//===-- NativeRegisterContextFreeBSD_ppc64le.cpp --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__powerpc64__) && defined(__LITTLE_ENDIAN__)

#include "NativeRegisterContextFreeBSD_ppc64le.h"

#include "lldb/Host/HostInfo.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"
// for register enum definitions
#include "Plugins/Process/Utility/RegisterContextPOSIX_ppc64le.h"

// clang-format off
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/types.h>
// clang-format on
#include <optional>

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_freebsd;

static const uint32_t g_gpr_regnums[] = {
    gpr_r0_ppc64le,  gpr_r1_ppc64le,  gpr_r2_ppc64le,  gpr_r3_ppc64le,
    gpr_r4_ppc64le,  gpr_r5_ppc64le,  gpr_r6_ppc64le,  gpr_r7_ppc64le,
    gpr_r8_ppc64le,  gpr_r9_ppc64le,  gpr_r10_ppc64le, gpr_r11_ppc64le,
    gpr_r12_ppc64le, gpr_r13_ppc64le, gpr_r14_ppc64le, gpr_r15_ppc64le,
    gpr_r16_ppc64le, gpr_r17_ppc64le, gpr_r18_ppc64le, gpr_r19_ppc64le,
    gpr_r20_ppc64le, gpr_r21_ppc64le, gpr_r22_ppc64le, gpr_r23_ppc64le,
    gpr_r24_ppc64le, gpr_r25_ppc64le, gpr_r26_ppc64le, gpr_r27_ppc64le,
    gpr_r28_ppc64le, gpr_r29_ppc64le, gpr_r30_ppc64le, gpr_r31_ppc64le,
    gpr_lr_ppc64le,  gpr_cr_ppc64le,  gpr_xer_ppc64le, gpr_ctr_ppc64le,
    gpr_pc_ppc64le,
};

static const uint32_t g_fpr_regnums[] = {
    fpr_f0_ppc64le,    fpr_f1_ppc64le,  fpr_f2_ppc64le,  fpr_f3_ppc64le,
    fpr_f4_ppc64le,    fpr_f5_ppc64le,  fpr_f6_ppc64le,  fpr_f7_ppc64le,
    fpr_f8_ppc64le,    fpr_f9_ppc64le,  fpr_f10_ppc64le, fpr_f11_ppc64le,
    fpr_f12_ppc64le,   fpr_f13_ppc64le, fpr_f14_ppc64le, fpr_f15_ppc64le,
    fpr_f16_ppc64le,   fpr_f17_ppc64le, fpr_f18_ppc64le, fpr_f19_ppc64le,
    fpr_f20_ppc64le,   fpr_f21_ppc64le, fpr_f22_ppc64le, fpr_f23_ppc64le,
    fpr_f24_ppc64le,   fpr_f25_ppc64le, fpr_f26_ppc64le, fpr_f27_ppc64le,
    fpr_f28_ppc64le,   fpr_f29_ppc64le, fpr_f30_ppc64le, fpr_f31_ppc64le,
    fpr_fpscr_ppc64le,
};

// Number of register sets provided by this context.
enum { k_num_register_sets = 2 };

static const RegisterSet g_reg_sets_ppc64le[k_num_register_sets] = {
    {"General Purpose Registers", "gpr", k_num_gpr_registers_ppc64le,
     g_gpr_regnums},
    {"Floating Point Registers", "fpr", k_num_fpr_registers_ppc64le,
     g_fpr_regnums},
};

NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread) {
  return new NativeRegisterContextFreeBSD_ppc64le(target_arch, native_thread);
}

static RegisterInfoInterface *
CreateRegisterInfoInterface(const ArchSpec &target_arch) {
  return new RegisterContextFreeBSD_ppc64le(target_arch);
}

NativeRegisterContextFreeBSD_ppc64le::NativeRegisterContextFreeBSD_ppc64le(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread)
    : NativeRegisterContextRegisterInfo(
          native_thread, CreateRegisterInfoInterface(target_arch)) {}

RegisterContextFreeBSD_ppc64le &
NativeRegisterContextFreeBSD_ppc64le::GetRegisterInfo() const {
  return static_cast<RegisterContextFreeBSD_ppc64le &>(
      *m_register_info_interface_up);
}

uint32_t NativeRegisterContextFreeBSD_ppc64le::GetRegisterSetCount() const {
  return k_num_register_sets;
}

const RegisterSet *
NativeRegisterContextFreeBSD_ppc64le::GetRegisterSet(uint32_t set_index) const {
  switch (GetRegisterInfoInterface().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::ppc64le:
    return &g_reg_sets_ppc64le[set_index];
  default:
    llvm_unreachable("Unhandled target architecture.");
  }
}

std::optional<NativeRegisterContextFreeBSD_ppc64le::RegSetKind>
NativeRegisterContextFreeBSD_ppc64le::GetSetForNativeRegNum(
    uint32_t reg_num) const {
  switch (GetRegisterInfoInterface().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::ppc64le:
    if (reg_num >= k_first_gpr_ppc64le && reg_num <= k_last_gpr_ppc64le)
      return GPRegSet;
    if (reg_num >= k_first_fpr && reg_num <= k_last_fpr)
      return FPRegSet;
    break;
  default:
    llvm_unreachable("Unhandled target architecture.");
  }

  llvm_unreachable("Register does not belong to any register set");
}

uint32_t NativeRegisterContextFreeBSD_ppc64le::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

Status NativeRegisterContextFreeBSD_ppc64le::ReadRegisterSet(RegSetKind set) {
  switch (set) {
  case GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETREGS, m_thread.GetID(),
                                               m_reg_data.data());
  case FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETFPREGS, m_thread.GetID(),
                                               m_reg_data.data() + sizeof(reg));
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_ppc64le::ReadRegisterSet");
}

Status NativeRegisterContextFreeBSD_ppc64le::WriteRegisterSet(RegSetKind set) {
  switch (set) {
  case GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETREGS, m_thread.GetID(),
                                               m_reg_data.data());
  case FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETFPREGS, m_thread.GetID(),
                                               m_reg_data.data() + sizeof(reg));
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_ppc64le::WriteRegisterSet");
}

Status
NativeRegisterContextFreeBSD_ppc64le::ReadRegister(const RegisterInfo *reg_info,
                                                   RegisterValue &reg_value) {
  Status error;

  if (!reg_info) {
    error = Status::FromErrorString("reg_info NULL");
    return error;
  }

  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];

  if (reg == LLDB_INVALID_REGNUM)
    return Status::FromErrorStringWithFormat(
        "no lldb regnum for %s",
        reg_info && reg_info->name ? reg_info->name : "<unknown register>");

  std::optional<RegSetKind> opt_set = GetSetForNativeRegNum(reg);
  if (!opt_set) {
    // This is likely an internal register for lldb use only and should not be
    // directly queried.
    error = Status::FromErrorStringWithFormat(
        "register \"%s\" is in unrecognized set", reg_info->name);
    return error;
  }

  RegSetKind set = *opt_set;
  error = ReadRegisterSet(set);
  if (error.Fail())
    return error;

  assert(reg_info->byte_offset + reg_info->byte_size <= m_reg_data.size());
  reg_value.SetBytes(m_reg_data.data() + reg_info->byte_offset,
                     reg_info->byte_size, endian::InlHostByteOrder());
  return error;
}

Status NativeRegisterContextFreeBSD_ppc64le::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  Status error;

  if (!reg_info)
    return Status::FromErrorString("reg_info NULL");

  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];

  if (reg == LLDB_INVALID_REGNUM)
    return Status::FromErrorStringWithFormat(
        "no lldb regnum for %s",
        reg_info && reg_info->name ? reg_info->name : "<unknown register>");

  std::optional<RegSetKind> opt_set = GetSetForNativeRegNum(reg);
  if (!opt_set) {
    // This is likely an internal register for lldb use only and should not be
    // directly queried.
    error = Status::FromErrorStringWithFormat(
        "register \"%s\" is in unrecognized set", reg_info->name);
    return error;
  }

  RegSetKind set = *opt_set;
  error = ReadRegisterSet(set);
  if (error.Fail())
    return error;

  assert(reg_info->byte_offset + reg_info->byte_size <= m_reg_data.size());
  ::memcpy(m_reg_data.data() + reg_info->byte_offset, reg_value.GetBytes(),
           reg_info->byte_size);

  return WriteRegisterSet(set);
}

Status NativeRegisterContextFreeBSD_ppc64le::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error;

  error = ReadRegisterSet(GPRegSet);
  if (error.Fail())
    return error;

  error = ReadRegisterSet(FPRegSet);
  if (error.Fail())
    return error;

  data_sp.reset(new DataBufferHeap(m_reg_data.size(), 0));
  uint8_t *dst = data_sp->GetBytes();
  ::memcpy(dst, m_reg_data.data(), m_reg_data.size());

  return error;
}

Status NativeRegisterContextFreeBSD_ppc64le::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextFreeBSD_ppc64le::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != m_reg_data.size()) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextFreeBSD_ppc64le::%s data_sp contained mismatched "
        "data size, expected %zu, actual %" PRIu64,
        __FUNCTION__, m_reg_data.size(), data_sp->GetByteSize());
    return error;
  }

  const uint8_t *src = data_sp->GetBytes();
  if (src == nullptr) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextFreeBSD_ppc64le::%s "
        "DataBuffer::GetBytes() returned a null "
        "pointer",
        __FUNCTION__);
    return error;
  }
  ::memcpy(m_reg_data.data(), src, m_reg_data.size());

  error = WriteRegisterSet(GPRegSet);
  if (error.Fail())
    return error;

  return WriteRegisterSet(FPRegSet);
}

llvm::Error NativeRegisterContextFreeBSD_ppc64le::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  return llvm::Error::success();
}

#endif // defined(__powerpc64__) && defined(__LITTLE_ENDIAN__)
