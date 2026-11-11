//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__riscv) && __riscv_xlen == 64

#include "NativeRegisterContextFreeBSD_riscv64.h"
#include "NativeProcessFreeBSD.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/Utility/DataBufferHeap.h"
#include <cstring>

// clang-format off
#include <sys/types.h>
#include <sys/ptrace.h>
#include <machine/reg.h>
// clang-format on


namespace reg_ids = lldb_private::registers::riscv::id;
using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_freebsd;

static_assert(sizeof(freebsd_riscv64::GPR) == sizeof(reg));
static_assert(offsetof(freebsd_riscv64::GPR, t) == offsetof(reg, t));
static_assert(offsetof(freebsd_riscv64::GPR, s) == offsetof(reg, s));
static_assert(offsetof(freebsd_riscv64::GPR, a) == offsetof(reg, a));
static_assert(offsetof(freebsd_riscv64::GPR, sepc) == offsetof(reg, sepc));
static_assert(sizeof(freebsd_riscv64::FPR) == sizeof(fpreg));
static_assert(offsetof(freebsd_riscv64::FPR, fcsr) == offsetof(fpreg, fp_fcsr));

NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &arch, NativeThreadFreeBSD &thread) {
  freebsd_riscv64::FPR fp{};
  bool has_fp =
      NativeProcessFreeBSD::PtraceWrapper(PT_GETFPREGS, thread.GetID(), &fp)
          .Success();
  return new NativeRegisterContextFreeBSD_riscv64(arch, thread, has_fp);
}

NativeRegisterContextFreeBSD_riscv64::NativeRegisterContextFreeBSD_riscv64(
    const ArchSpec &arch, NativeThreadFreeBSD &thread, bool has_fp)
    : NativeRegisterContext(thread, arch,
                            CreateFreeBSDRISCV64RegisterLayout(arch, has_fp)),
      m_has_fp(has_fp) {}

Status NativeRegisterContextFreeBSD_riscv64::ReadBank(RegisterBankID bank) {
  switch (bank) {
  case 0:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETREGS, m_thread.GetID(),
                                               &m_gpr);
  case 1:
    if (m_has_fp)
      return NativeProcessFreeBSD::PtraceWrapper(PT_GETFPREGS, m_thread.GetID(),
                                                 &m_fpr);
    break;
  }
  return Status::FromErrorString("unsupported register bank");
}

Status NativeRegisterContextFreeBSD_riscv64::WriteBank(RegisterBankID bank) {
  switch (bank) {
  case 0:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETREGS, m_thread.GetID(),
                                               &m_gpr);
  case 1:
    if (m_has_fp)
      return NativeProcessFreeBSD::PtraceWrapper(PT_SETFPREGS, m_thread.GetID(),
                                                 &m_fpr);
    break;
  }
  return Status::FromErrorString("unsupported register bank");
}

llvm::Expected<RegisterValue>
NativeRegisterContextFreeBSD_riscv64::ReadRegister(RegisterID id) {
  auto banks = GetLayout().GetRequiredBanks(id);
  if (!banks)
    return banks.takeError();
  for (RegisterBankID bank : *banks)
    if (Status error = ReadBank(bank); error.Fail())
      return error.ToError();
  return ReadBankRegister(
      id, {{0, {reinterpret_cast<const uint8_t *>(&m_gpr), sizeof(m_gpr)}},
           {1, {reinterpret_cast<const uint8_t *>(&m_fpr), sizeof(m_fpr)}}});
}

llvm::Error NativeRegisterContextFreeBSD_riscv64::WriteRegister(
    RegisterID id, const RegisterValue &value) {
  // Like the hardware, accept and ignore writes to the zero register.
  if (id == reg_ids::gpr_x0)
    return llvm::Error::success();
  auto banks = GetLayout().GetRequiredBanks(id, true);
  if (!banks)
    return banks.takeError();
  // Preserve the status register and unused portions of the FP slots.
  for (RegisterBankID bank : *banks)
    if (Status error = ReadBank(bank); error.Fail())
      return error.ToError();
  if (auto error = WriteBankRegister(
          id, value,
          {{0, {reinterpret_cast<uint8_t *>(&m_gpr), sizeof(m_gpr)}},
           {1, {reinterpret_cast<uint8_t *>(&m_fpr), sizeof(m_fpr)}}}))
    return error;
  for (RegisterBankID bank : *banks)
    if (Status error = WriteBank(bank); error.Fail())
      return error.ToError();
  return llvm::Error::success();
}

Status NativeRegisterContextFreeBSD_riscv64::ReadAllRegisterValues(
    WritableDataBufferSP &data) {
  Status error = ReadBank(0);
  if (error.Fail())
    return error;
  if (m_has_fp) {
    error = ReadBank(1);
    if (error.Fail())
      return error;
  }
  data = std::make_shared<DataBufferHeap>(
      sizeof(m_gpr) + (m_has_fp ? sizeof(m_fpr) : 0), 0);
  std::memcpy(data->GetBytes(), &m_gpr, sizeof(m_gpr));
  if (m_has_fp)
    std::memcpy(data->GetBytes() + sizeof(m_gpr), &m_fpr, sizeof(m_fpr));
  return Status();
}

Status NativeRegisterContextFreeBSD_riscv64::WriteAllRegisterValues(
    const DataBufferSP &data) {
  if (!data ||
      data->GetByteSize() != sizeof(m_gpr) + (m_has_fp ? sizeof(m_fpr) : 0))
    return Status::FromErrorString("invalid private register checkpoint");
  std::memcpy(&m_gpr, data->GetBytes(), sizeof(m_gpr));
  if (m_has_fp)
    std::memcpy(&m_fpr, data->GetBytes() + sizeof(m_gpr), sizeof(m_fpr));
  Status error = WriteBank(0);
  if (error.Fail() || !m_has_fp)
    return error;
  return WriteBank(1);
}

llvm::Error NativeRegisterContextFreeBSD_riscv64::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  return llvm::Error::success();
}

#endif
