//===-- NativeRegisterContextFreeBSD_arm64.cpp ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__aarch64__)

#include "NativeRegisterContextFreeBSD_arm64.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterModelFreeBSD_arm64.h"

#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
#include "Plugins/Process/Utility/AuxVector.h"
#include "lldb/Register/Common/RegisterInfo_arm64.h"

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
  return new NativeRegisterContextFreeBSD_arm64(target_arch, native_thread);
}

NativeRegisterContextFreeBSD_arm64::NativeRegisterContextFreeBSD_arm64(
    const ArchSpec &target_arch, NativeThreadFreeBSD &native_thread)
    : NativeRegisterContextRegisterInfo(
          native_thread,
          new RegisterInfo_arm64(
              target_arch, 0,
              CreateFreeBSDArm64RegisterModel(
                  target_arch,
                  native_thread.GetProcess()
                      .GetAuxValue(AuxVector::AUXV_FREEBSD_AT_HWCAP)
                      .value_or(0),
                  native_thread.GetProcess()
                      .GetAuxValue(AuxVector::AUXV_AT_HWCAP2)
                      .value_or(0)))),
      m_read_dbreg(false) {}

RegisterInfo_arm64 &
NativeRegisterContextFreeBSD_arm64::GetRegisterInfo() const {
  return static_cast<RegisterInfo_arm64 &>(*m_register_info_interface_up);
}

uint32_t NativeRegisterContextFreeBSD_arm64::GetRegisterSetCount() const {
  return GetRegisterInfo().GetRegisterSetCount();
}

const RegisterSet *
NativeRegisterContextFreeBSD_arm64::GetRegisterSet(uint32_t set_index) const {
  return GetRegisterInfo().GetRegisterSet(set_index);
}

uint32_t NativeRegisterContextFreeBSD_arm64::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

Status NativeRegisterContextFreeBSD_arm64::ReadRegisterSet(uint32_t set) {
  switch (set) {
  case RegisterInfo_arm64::GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETREGS, m_thread.GetID(),
                                               &m_gpr);
  case RegisterInfo_arm64::FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETFPREGS, m_thread.GetID(),
                                               &m_fpr);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_arm64::ReadRegisterSet");
}

Status NativeRegisterContextFreeBSD_arm64::WriteRegisterSet(uint32_t set) {
  switch (set) {
  case RegisterInfo_arm64::GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETREGS, m_thread.GetID(),
                                               &m_gpr);
  case RegisterInfo_arm64::FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETFPREGS, m_thread.GetID(),
                                               &m_fpr);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_arm64::WriteRegisterSet");
}

Status
NativeRegisterContextFreeBSD_arm64::ReadRegister(const RegisterInfo *reg_info,
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
      status = ReadRegisterSet(RegisterInfo_arm64::GPRegSet);
      break;
    case 1:
      status = ReadRegisterSet(RegisterInfo_arm64::FPRegSet);
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

Status NativeRegisterContextFreeBSD_arm64::WriteRegister(
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
      status = ReadRegisterSet(RegisterInfo_arm64::GPRegSet);
      break;
    case 1:
      status = ReadRegisterSet(RegisterInfo_arm64::FPRegSet);
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
      status = WriteRegisterSet(RegisterInfo_arm64::GPRegSet);
      break;
    case 1:
      status = WriteRegisterSet(RegisterInfo_arm64::FPRegSet);
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  return Status();
}

Status NativeRegisterContextFreeBSD_arm64::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error = ReadRegisterSet(RegisterInfo_arm64::GPRegSet);
  if (error.Fail())
    return error;
  error = ReadRegisterSet(RegisterInfo_arm64::FPRegSet);
  if (error.Fail())
    return error;
  data_sp = std::make_shared<DataBufferHeap>(sizeof(m_gpr) + sizeof(m_fpr), 0);
  std::memcpy(data_sp->GetBytes(), &m_gpr, sizeof(m_gpr));
  std::memcpy(data_sp->GetBytes() + sizeof(m_gpr), &m_fpr, sizeof(m_fpr));
  return Status();
}

Status NativeRegisterContextFreeBSD_arm64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  if (!data_sp || data_sp->GetByteSize() != sizeof(m_gpr) + sizeof(m_fpr))
    return Status::FromErrorString("invalid private register checkpoint");
  std::memcpy(&m_gpr, data_sp->GetBytes(), sizeof(m_gpr));
  std::memcpy(&m_fpr, data_sp->GetBytes() + sizeof(m_gpr), sizeof(m_fpr));
  Status error = WriteRegisterSet(RegisterInfo_arm64::GPRegSet);
  return error.Fail() ? error : WriteRegisterSet(RegisterInfo_arm64::FPRegSet);
}

llvm::Error NativeRegisterContextFreeBSD_arm64::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  auto &r_source = static_cast<NativeRegisterContextFreeBSD_arm64 &>(source);
  llvm::Error error = r_source.ReadHardwareDebugInfo();
  if (error)
    return error;

  m_dbreg = r_source.m_dbreg;
  m_hbp_regs = r_source.m_hbp_regs;
  m_hwp_regs = r_source.m_hwp_regs;
  m_max_hbp_supported = r_source.m_max_hbp_supported;
  m_max_hwp_supported = r_source.m_max_hwp_supported;
  m_read_dbreg = true;

  // on FreeBSD this writes both breakpoints and watchpoints
  return WriteHardwareDebugRegs(eDREGTypeWATCH);
}

llvm::Error NativeRegisterContextFreeBSD_arm64::ReadHardwareDebugInfo() {
  Log *log = GetLog(POSIXLog::Registers);

  // we're fully stateful, so no need to reread control registers ever
  if (m_read_dbreg)
    return llvm::Error::success();

  Status res = NativeProcessFreeBSD::PtraceWrapper(PT_GETDBREGS,
                                                   m_thread.GetID(), &m_dbreg);
  if (res.Fail())
    return res.ToError();

  LLDB_LOG(log, "m_dbreg read: debug_ver={0}, nbkpts={1}, nwtpts={2}",
           m_dbreg.db_debug_ver, m_dbreg.db_nbkpts, m_dbreg.db_nwtpts);
  m_max_hbp_supported = m_dbreg.db_nbkpts;
  m_max_hwp_supported = m_dbreg.db_nwtpts;
  assert(m_max_hbp_supported <= m_hbp_regs.size());
  assert(m_max_hwp_supported <= m_hwp_regs.size());

  m_read_dbreg = true;
  return llvm::Error::success();
}

llvm::Error
NativeRegisterContextFreeBSD_arm64::WriteHardwareDebugRegs(DREGType) {
  assert(m_read_dbreg && "dbregs must be read before writing them back");

  // copy data from m_*_regs to m_dbreg before writing it back
  for (uint32_t i = 0; i < m_max_hbp_supported; i++) {
    m_dbreg.db_breakregs[i].dbr_addr = m_hbp_regs[i].address;
    m_dbreg.db_breakregs[i].dbr_ctrl = m_hbp_regs[i].control;
  }
  for (uint32_t i = 0; i < m_max_hwp_supported; i++) {
    m_dbreg.db_watchregs[i].dbw_addr = m_hwp_regs[i].address;
    m_dbreg.db_watchregs[i].dbw_ctrl = m_hwp_regs[i].control;
  }

  return NativeProcessFreeBSD::PtraceWrapper(PT_SETDBREGS, m_thread.GetID(),
                                             &m_dbreg)
      .ToError();
}

#endif // defined (__aarch64__)
