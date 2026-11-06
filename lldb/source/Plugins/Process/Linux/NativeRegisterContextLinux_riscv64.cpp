//===-- NativeRegisterContextLinux_riscv64.cpp ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__riscv) && __riscv_xlen == 64

#include "NativeRegisterContextLinux_riscv64.h"

#include "Plugins/Process/Linux/NativeProcessLinux.h"
#include "Plugins/Process/Linux/Procfs.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_riscv64.h"
#include "lldb/Register/RegisterCodec.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

// System includes - They have to be included after framework includes because
// they define some macros which collide with variable names in other modules
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_linux;

std::unique_ptr<NativeRegisterContextLinux>
NativeRegisterContextLinux::CreateHostNativeRegisterContextLinux(
    const ArchSpec &target_arch, NativeThreadLinux &native_thread) {
  switch (target_arch.GetMachine()) {
  case llvm::Triple::riscv64: {
    Flags opt_regsets(RegisterInfo_riscv64::eRegsetMaskDefault);

    linux_riscv64::FPR fpr;
    struct iovec ioVec;
    ioVec.iov_base = &fpr;
    ioVec.iov_len = sizeof(fpr);
    unsigned int regset = NT_FPREGSET;

    if (NativeProcessLinux::PtraceWrapper(PTRACE_GETREGSET,
                                          native_thread.GetID(), &regset,
                                          &ioVec, sizeof(fpr))
            .Success()) {
      opt_regsets.Set(RegisterInfo_riscv64::eRegsetMaskFP);
    }

    auto register_info_up = std::make_unique<RegisterInfo_riscv64>(
        target_arch, opt_regsets,
        CreateLinuxRISCV64RegisterModel(target_arch, opt_regsets));
    return std::make_unique<NativeRegisterContextLinux_riscv64>(
        target_arch, native_thread, std::move(register_info_up));
  }
  default:
    llvm_unreachable("have no register context for architecture");
  }
}

llvm::Expected<ArchSpec>
NativeRegisterContextLinux::DetermineArchitecture(lldb::tid_t tid) {
  return HostInfo::GetArchitecture();
}

NativeRegisterContextLinux_riscv64::NativeRegisterContextLinux_riscv64(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread,
    std::unique_ptr<RegisterInfo_riscv64> register_info_up)
    : NativeRegisterContextRegisterInfo(native_thread,
                                        register_info_up.release()),
      NativeRegisterContextLinux(native_thread) {
  ::memset(&m_fpr, 0, sizeof(m_fpr));
  ::memset(&m_gpr, 0, sizeof(m_gpr));

  m_gpr_is_valid = false;
  m_fpu_is_valid = false;
}

const RegisterInfo_riscv64 &
NativeRegisterContextLinux_riscv64::GetRegisterInfo() const {
  return static_cast<const RegisterInfo_riscv64 &>(
      NativeRegisterContextRegisterInfo::GetRegisterInfoProvider());
}

uint32_t NativeRegisterContextLinux_riscv64::GetRegisterSetCount() const {
  return GetRegisterInfo().GetRegisterSetCount();
}

const RegisterSet *
NativeRegisterContextLinux_riscv64::GetRegisterSet(uint32_t set_index) const {
  return GetRegisterInfo().GetRegisterSet(set_index);
}

uint32_t NativeRegisterContextLinux_riscv64::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

Status
NativeRegisterContextLinux_riscv64::ReadRegister(const RegisterInfo *reg_info,
                                                 RegisterValue &reg_value) {
  if (!reg_info || !reg_info->name)
    return Status::FromErrorString("invalid register description");
  const auto &provider = GetRegisterInfo();
  const auto *reg = provider.GetDescription().Find(reg_info->name);
  if (!reg)
    return Status::FromErrorString("unknown register");
  std::vector<RegisterData> banks;
  if (reg->id != gpr_x0_riscv) {
    bool general = IsGPR(reg_info->kinds[lldb::eRegisterKindLLDB]);
    Status error = general ? ReadGPR() : ReadFPR();
    if (error.Fail())
      return error;
    banks.push_back({general ? 0u : 1u,
                     {static_cast<const uint8_t *>(general ? GetGPRBuffer()
                                                           : GetFPRBuffer()),
                      general ? GetGPRSize() : GetFPRSize()}});
  }
  auto result = RegisterCodec::Read(provider.GetDescription(),
                                    provider.GetLayout(), reg->id, banks);
  if (!result)
    return Status::FromError(result.takeError());
  reg_value = std::move(*result);
  return Status();
}

Status NativeRegisterContextLinux_riscv64::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  if (!reg_info || !reg_info->name)
    return Status::FromErrorString("invalid register description");
  const auto &provider = GetRegisterInfo();
  const auto *reg = provider.GetDescription().Find(reg_info->name);
  if (!reg)
    return Status::FromErrorString("unknown register");
  if (reg->id == gpr_x0_riscv)
    return Status(); // Writes to architectural x0 have no effect.
  bool general = IsGPR(reg_info->kinds[lldb::eRegisterKindLLDB]);
  Status error = general ? ReadGPR() : ReadFPR();
  if (error.Fail())
    return error;
  MutableRegisterData bank{
      general ? 0u : 1u,
      {static_cast<uint8_t *>(general ? GetGPRBuffer() : GetFPRBuffer()),
       general ? GetGPRSize() : GetFPRSize()}};
  if (llvm::Error error =
          RegisterCodec::Write(provider.GetDescription(), provider.GetLayout(),
                               reg->id, reg_value, bank))
    return Status::FromError(std::move(error));
  return general ? WriteGPR() : WriteFPR();
}

Status NativeRegisterContextLinux_riscv64::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error;

  data_sp.reset(new DataBufferHeap(GetRegContextSize(), 0));

  error = ReadGPR();
  if (error.Fail())
    return error;

  if (GetRegisterInfo().IsFPPresent()) {
    error = ReadFPR();
    if (error.Fail())
      return error;
  }

  uint8_t *dst = const_cast<uint8_t *>(data_sp->GetBytes());
  ::memcpy(dst, GetGPRBuffer(), GetGPRSize());
  dst += GetGPRSize();
  if (GetRegisterInfo().IsFPPresent())
    ::memcpy(dst, GetFPRBuffer(), GetFPRSize());

  return error;
}

Status NativeRegisterContextLinux_riscv64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_riscv64::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != GetRegContextSize()) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_riscv64::%s data_sp contained mismatched "
        "data size, expected %" PRIu64 ", actual %" PRIu64,
        __FUNCTION__, GetRegContextSize(), data_sp->GetByteSize());
    return error;
  }

  uint8_t *src = const_cast<uint8_t *>(data_sp->GetBytes());
  if (src == nullptr) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_riscv64::%s "
        "DataBuffer::GetBytes() returned a null "
        "pointer",
        __FUNCTION__);
    return error;
  }
  ::memcpy(GetGPRBuffer(), src, GetRegisterInfoProvider().GetGPRSize());

  error = WriteGPR();
  if (error.Fail())
    return error;

  src += GetRegisterInfoProvider().GetGPRSize();

  if (GetRegisterInfo().IsFPPresent()) {
    ::memcpy(GetFPRBuffer(), src, GetFPRSize());

    error = WriteFPR();
    if (error.Fail())
      return error;
  }

  return error;
}

size_t NativeRegisterContextLinux_riscv64::GetRegContextSize() {
  size_t size = GetGPRSize();
  if (GetRegisterInfo().IsFPPresent())
    size += GetFPRSize();
  return size;
}

bool NativeRegisterContextLinux_riscv64::IsGPR(unsigned reg) const {
  return GetRegisterInfo().GetRegisterSetFromRegisterNumber(reg) ==
         linux_riscv64::GPRegSet;
}

bool NativeRegisterContextLinux_riscv64::IsFPR(unsigned reg) const {
  return GetRegisterInfo().IsFPReg(reg);
}

Status NativeRegisterContextLinux_riscv64::ReadGPR() {
  Status error;

  if (m_gpr_is_valid)
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetGPRBuffer();
  ioVec.iov_len = GetGPRSize();

  error = ReadRegisterSet(&ioVec, GetGPRSize(), NT_PRSTATUS);

  if (error.Success())
    m_gpr_is_valid = true;

  return error;
}

Status NativeRegisterContextLinux_riscv64::WriteGPR() {
  Status error = ReadGPR();
  if (error.Fail())
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetGPRBuffer();
  ioVec.iov_len = GetGPRSize();

  m_gpr_is_valid = false;

  return WriteRegisterSet(&ioVec, GetGPRSize(), NT_PRSTATUS);
}

Status NativeRegisterContextLinux_riscv64::ReadFPR() {
  Status error;

  if (m_fpu_is_valid)
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetFPRBuffer();
  ioVec.iov_len = GetFPRSize();

  error = ReadRegisterSet(&ioVec, GetFPRSize(), NT_FPREGSET);

  if (error.Success())
    m_fpu_is_valid = true;

  return error;
}

Status NativeRegisterContextLinux_riscv64::WriteFPR() {
  Status error = ReadFPR();
  if (error.Fail())
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetFPRBuffer();
  ioVec.iov_len = GetFPRSize();

  m_fpu_is_valid = false;

  return WriteRegisterSet(&ioVec, GetFPRSize(), NT_FPREGSET);
}

void NativeRegisterContextLinux_riscv64::InvalidateAllRegisters() {
  m_gpr_is_valid = false;
  m_fpu_is_valid = false;
}

std::vector<uint32_t> NativeRegisterContextLinux_riscv64::GetExpeditedRegisters(
    ExpeditedRegs expType) const {
  std::vector<uint32_t> expedited_reg_nums =
      NativeRegisterContext::GetExpeditedRegisters(expType);

  return expedited_reg_nums;
}

#endif // defined (__riscv) && __riscv_xlen == 64
