//===-- NativeRegisterContextFreeBSD_powerpc.cpp --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__powerpc__)

#include "NativeRegisterContextFreeBSD_powerpc.h"

#include "lldb/Host/HostInfo.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"
#include "lldb/Register/Arch/lldb-powerpc-register-enums.h"

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
    gpr_r0_powerpc,  gpr_r1_powerpc,  gpr_r2_powerpc,  gpr_r3_powerpc,
    gpr_r4_powerpc,  gpr_r5_powerpc,  gpr_r6_powerpc,  gpr_r7_powerpc,
    gpr_r8_powerpc,  gpr_r9_powerpc,  gpr_r10_powerpc, gpr_r11_powerpc,
    gpr_r12_powerpc, gpr_r13_powerpc, gpr_r14_powerpc, gpr_r15_powerpc,
    gpr_r16_powerpc, gpr_r17_powerpc, gpr_r18_powerpc, gpr_r19_powerpc,
    gpr_r20_powerpc, gpr_r21_powerpc, gpr_r22_powerpc, gpr_r23_powerpc,
    gpr_r24_powerpc, gpr_r25_powerpc, gpr_r26_powerpc, gpr_r27_powerpc,
    gpr_r28_powerpc, gpr_r29_powerpc, gpr_r30_powerpc, gpr_r31_powerpc,
    gpr_lr_powerpc,  gpr_cr_powerpc,  gpr_xer_powerpc, gpr_ctr_powerpc,
    gpr_pc_powerpc,
};

static const uint32_t g_fpr_regnums[] = {
    fpr_f0_powerpc,    fpr_f1_powerpc,  fpr_f2_powerpc,  fpr_f3_powerpc,
    fpr_f4_powerpc,    fpr_f5_powerpc,  fpr_f6_powerpc,  fpr_f7_powerpc,
    fpr_f8_powerpc,    fpr_f9_powerpc,  fpr_f10_powerpc, fpr_f11_powerpc,
    fpr_f12_powerpc,   fpr_f13_powerpc, fpr_f14_powerpc, fpr_f15_powerpc,
    fpr_f16_powerpc,   fpr_f17_powerpc, fpr_f18_powerpc, fpr_f19_powerpc,
    fpr_f20_powerpc,   fpr_f21_powerpc, fpr_f22_powerpc, fpr_f23_powerpc,
    fpr_f24_powerpc,   fpr_f25_powerpc, fpr_f26_powerpc, fpr_f27_powerpc,
    fpr_f28_powerpc,   fpr_f29_powerpc, fpr_f30_powerpc, fpr_f31_powerpc,
    fpr_fpscr_powerpc,
};

// Number of register sets provided by this context.
enum { k_num_register_sets = 2 };

static const RegisterSet g_reg_sets_powerpc[k_num_register_sets] = {
    {"General Purpose Registers", "gpr", k_num_gpr_registers_powerpc,
     g_gpr_regnums},
    {"Floating Point Registers", "fpr", k_num_fpr_registers_powerpc,
     g_fpr_regnums},
};

NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread) {
  return new NativeRegisterContextFreeBSD_powerpc(target_arch, native_thread);
}

static RegisterInfoProvider *
CreateRegisterInfoInterface(const ArchSpec &target_arch) {
  if (HostInfo::GetArchitecture().GetAddressByteSize() == 4) {
    return new RegisterInfo_powerpc(
        target_arch, CreateFreeBSDPowerPC32RegisterModel(target_arch));
  } else {
    assert((HostInfo::GetArchitecture().GetAddressByteSize() == 8) &&
           "Register setting path assumes this is a 64-bit host");
    return new RegisterInfo_powerpc(
        target_arch, CreateFreeBSDPowerPC64RegisterModel(target_arch));
  }
}

NativeRegisterContextFreeBSD_powerpc::NativeRegisterContextFreeBSD_powerpc(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread)
    : NativeRegisterContextRegisterInfo(
          native_thread, CreateRegisterInfoInterface(target_arch)) {}

RegisterInfo_powerpc &
NativeRegisterContextFreeBSD_powerpc::GetRegisterInfo() const {
  return static_cast<RegisterInfo_powerpc &>(*m_register_info_interface_up);
}

uint32_t NativeRegisterContextFreeBSD_powerpc::GetRegisterSetCount() const {
  return k_num_register_sets;
}

const RegisterSet *
NativeRegisterContextFreeBSD_powerpc::GetRegisterSet(uint32_t set_index) const {
  switch (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::ppc:
    return &g_reg_sets_powerpc[set_index];
  default:
    llvm_unreachable("Unhandled target architecture.");
  }
}

std::optional<NativeRegisterContextFreeBSD_powerpc::RegSetKind>
NativeRegisterContextFreeBSD_powerpc::GetSetForNativeRegNum(
    uint32_t reg_num) const {
  switch (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::ppc:
    if (reg_num >= k_first_gpr_powerpc && reg_num <= k_last_gpr_powerpc)
      return GPRegSet;
    if (reg_num >= k_first_fpr && reg_num <= k_last_fpr)
      return FPRegSet;
    break;
  default:
    llvm_unreachable("Unhandled target architecture.");
  }

  llvm_unreachable("Register does not belong to any register set");
}

uint32_t NativeRegisterContextFreeBSD_powerpc::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

Status NativeRegisterContextFreeBSD_powerpc::ReadRegisterSet(RegSetKind set) {
  switch (set) {
  case GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETREGS, m_thread.GetID(),
                                               &m_gpr);
  case FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETFPREGS, m_thread.GetID(),
                                               &m_fpr);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_powerpc::ReadRegisterSet");
}

Status NativeRegisterContextFreeBSD_powerpc::WriteRegisterSet(RegSetKind set) {
  switch (set) {
  case GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETREGS, m_thread.GetID(),
                                               &m_gpr);
  case FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETFPREGS, m_thread.GetID(),
                                               &m_fpr);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_powerpc::WriteRegisterSet");
}

Status
NativeRegisterContextFreeBSD_powerpc::ReadRegister(const RegisterInfo *reg_info,
                                                   RegisterValue &reg_value) {
  if (!reg_info)
    return Status::FromErrorString("missing register description");
  const auto &provider = GetRegisterInfoProvider();
  auto required = provider.GetRegisterBanks(*reg_info, false);
  if (!required)
    return Status::FromError(required.takeError());
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case 0:
      status = ReadRegisterSet(GPRegSet);
      break;
    case 1:
      status = ReadRegisterSet(FPRegSet);
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  auto value = provider.ReadRegister(
      *reg_info,
      {{0, {reinterpret_cast<const uint8_t *>(&m_gpr), sizeof(m_gpr)}},
       {1, {reinterpret_cast<const uint8_t *>(&m_fpr), sizeof(m_fpr)}}});
  if (!value)
    return Status::FromError(value.takeError());
  reg_value = std::move(*value);
  return Status();
}

Status NativeRegisterContextFreeBSD_powerpc::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  if (!reg_info)
    return Status::FromErrorString("missing register description");
  const auto &provider = GetRegisterInfoProvider();
  auto required = provider.GetRegisterBanks(*reg_info, true);
  if (!required)
    return Status::FromError(required.takeError());
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case 0:
      status = ReadRegisterSet(GPRegSet);
      break;
    case 1:
      status = ReadRegisterSet(FPRegSet);
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  if (auto error = provider.WriteRegister(
          *reg_info, reg_value,
          {{0, {reinterpret_cast<uint8_t *>(&m_gpr), sizeof(m_gpr)}},
           {1, {reinterpret_cast<uint8_t *>(&m_fpr), sizeof(m_fpr)}}}))
    return Status::FromError(std::move(error));
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case 0:
      status = WriteRegisterSet(GPRegSet);
      break;
    case 1:
      status = WriteRegisterSet(FPRegSet);
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  return Status();
}

Status NativeRegisterContextFreeBSD_powerpc::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error = ReadRegisterSet(GPRegSet);
  if (error.Fail())
    return error;
  error = ReadRegisterSet(FPRegSet);
  if (error.Fail())
    return error;
  data_sp = std::make_shared<DataBufferHeap>(sizeof(m_gpr) + sizeof(m_fpr), 0);
  std::memcpy(data_sp->GetBytes(), &m_gpr, sizeof(m_gpr));
  std::memcpy(data_sp->GetBytes() + sizeof(m_gpr), &m_fpr, sizeof(m_fpr));
  return Status();
}

Status NativeRegisterContextFreeBSD_powerpc::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  if (!data_sp || data_sp->GetByteSize() != sizeof(m_gpr) + sizeof(m_fpr))
    return Status::FromErrorString("invalid private register checkpoint");
  std::memcpy(&m_gpr, data_sp->GetBytes(), sizeof(m_gpr));
  std::memcpy(&m_fpr, data_sp->GetBytes() + sizeof(m_gpr), sizeof(m_fpr));
  Status error = WriteRegisterSet(GPRegSet);
  return error.Fail() ? error : WriteRegisterSet(FPRegSet);
}

llvm::Error NativeRegisterContextFreeBSD_powerpc::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  return llvm::Error::success();
}

#endif // defined (__powerpc__)
