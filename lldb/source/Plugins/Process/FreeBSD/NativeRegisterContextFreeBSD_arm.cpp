//===-- NativeRegisterContextFreeBSD_arm.cpp ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__arm__)

#include "NativeRegisterContextFreeBSD_arm.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterModelFreeBSD_arm.h"

#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"
#include "lldb/Register/Common/RegisterInfo_arm.h"

// clang-format off
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/types.h>
// clang-format on

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_freebsd;

NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread) {
  return new NativeRegisterContextFreeBSD_arm(target_arch, native_thread);
}

NativeRegisterContextFreeBSD_arm::NativeRegisterContextFreeBSD_arm(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread)
    : NativeRegisterContextRegisterInfo(
          native_thread,
          new RegisterInfo_arm(target_arch,
                               CreateFreeBSDArmRegisterModel(target_arch))) {}

RegisterInfo_arm &NativeRegisterContextFreeBSD_arm::GetRegisterInfo() const {
  return static_cast<RegisterInfo_arm &>(*m_register_info_interface_up);
}

uint32_t NativeRegisterContextFreeBSD_arm::GetRegisterSetCount() const {
  return GetRegisterInfo().GetRegisterSetCount();
}

const RegisterSet *
NativeRegisterContextFreeBSD_arm::GetRegisterSet(uint32_t set_index) const {
  return GetRegisterInfo().GetRegisterSet(set_index);
}

uint32_t NativeRegisterContextFreeBSD_arm::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

Status NativeRegisterContextFreeBSD_arm::ReadRegisterSet(uint32_t set) {
  switch (set) {
  case RegisterInfo_arm::GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETREGS, m_thread.GetID(),
                                               &m_gpr);
  case RegisterInfo_arm::FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETVFPREGS, m_thread.GetID(),
                                               &m_fpr);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_arm::ReadRegisterSet");
}

Status NativeRegisterContextFreeBSD_arm::WriteRegisterSet(uint32_t set) {
  switch (set) {
  case RegisterInfo_arm::GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETREGS, m_thread.GetID(),
                                               &m_gpr);
  case RegisterInfo_arm::FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETVFPREGS, m_thread.GetID(),
                                               &m_fpr);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_arm::WriteRegisterSet");
}

Status
NativeRegisterContextFreeBSD_arm::ReadRegister(const RegisterInfo *reg_info,
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
      status = ReadRegisterSet(RegisterInfo_arm::GPRegSet);
      break;
    case 1:
      status = ReadRegisterSet(RegisterInfo_arm::FPRegSet);
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

Status NativeRegisterContextFreeBSD_arm::WriteRegister(
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
      status = ReadRegisterSet(RegisterInfo_arm::GPRegSet);
      break;
    case 1:
      status = ReadRegisterSet(RegisterInfo_arm::FPRegSet);
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
      status = WriteRegisterSet(RegisterInfo_arm::GPRegSet);
      break;
    case 1:
      status = WriteRegisterSet(RegisterInfo_arm::FPRegSet);
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  return Status();
}

Status NativeRegisterContextFreeBSD_arm::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error = ReadRegisterSet(RegisterInfo_arm::GPRegSet);
  if (error.Fail())
    return error;
  error = ReadRegisterSet(RegisterInfo_arm::FPRegSet);
  if (error.Fail())
    return error;
  data_sp = std::make_shared<DataBufferHeap>(sizeof(m_gpr) + sizeof(m_fpr), 0);
  std::memcpy(data_sp->GetBytes(), &m_gpr, sizeof(m_gpr));
  std::memcpy(data_sp->GetBytes() + sizeof(m_gpr), &m_fpr, sizeof(m_fpr));
  return Status();
}

Status NativeRegisterContextFreeBSD_arm::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  if (!data_sp || data_sp->GetByteSize() != sizeof(m_gpr) + sizeof(m_fpr))
    return Status::FromErrorString("invalid private register checkpoint");
  std::memcpy(&m_gpr, data_sp->GetBytes(), sizeof(m_gpr));
  std::memcpy(&m_fpr, data_sp->GetBytes() + sizeof(m_gpr), sizeof(m_fpr));
  Status error = WriteRegisterSet(RegisterInfo_arm::GPRegSet);
  return error.Fail() ? error : WriteRegisterSet(RegisterInfo_arm::FPRegSet);
}

llvm::Error NativeRegisterContextFreeBSD_arm::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  return llvm::Error::success();
}

#endif // defined (__arm__)
