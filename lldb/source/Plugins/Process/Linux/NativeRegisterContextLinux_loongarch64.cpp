//===-- NativeRegisterContextLinux_loongarch64.cpp ------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__loongarch__) && __loongarch_grlen == 64

#include "NativeRegisterContextLinux_loongarch64.h"

#include "Plugins/Process/Linux/NativeProcessLinux.h"
#include "Plugins/Process/Linux/Procfs.h"
#include "lldb/Register/Common/RegisterInfo_loongarch64.h"
#include "lldb/Register/Arch/lldb-loongarch-register-enums.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

// System includes - They have to be included after framework includes because
// they define some macros which collide with variable names in other modules.
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif

#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

// LoongArch SIMD eXtension registers
#ifndef NT_LOONGARCH_LSX
#define NT_LOONGARCH_LSX 0xa02
#endif

// LoongArch Advanced SIMD eXtension registers
#ifndef NT_LOONGARCH_LASX
#define NT_LOONGARCH_LASX 0xa03
#endif

// LoongArch hardware breakpoint registers
#ifndef NT_LOONGARCH_HW_BREAK
#define NT_LOONGARCH_HW_BREAK 0xa05
#endif

// LoongArch hardware watchpoint registers
#ifndef NT_LOONGARCH_HW_WATCH
#define NT_LOONGARCH_HW_WATCH 0xa06
#endif

#define REG_CONTEXT_SIZE                                                       \
  (GetGPRSize() + GetFPRSize() + sizeof(m_lsx) + sizeof(m_lasx))

// ptrace has a struct type user_watch_state, which was replaced by
// user_watch_state_v2 when more watchpoints were added, so this file
// may be built on systems with one or both in the system headers.
// The type below has the same layout as user_watch_state_v2 but will
// not clash with that name if it exists. We can use the v2 layout even
// on old kernels as we will only see 8 watchpoints and the kernel will
// truncate any extra data we send to it.
struct loongarch_user_watch_state {
  uint64_t dbg_info;
  struct {
    uint64_t addr;
    uint64_t mask;
    uint32_t ctrl;
    uint32_t pad;
  } dbg_regs[14];
};

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_linux;

std::unique_ptr<NativeRegisterContextLinux>
NativeRegisterContextLinux::CreateHostNativeRegisterContextLinux(
    const ArchSpec &target_arch, NativeThreadLinux &native_thread) {
  switch (target_arch.GetMachine()) {
  case llvm::Triple::loongarch64: {
    auto register_info_up = std::make_unique<RegisterInfo_loongarch64>(
        target_arch, CreateLinuxLoongArch64RegisterModel(target_arch));
    return std::make_unique<NativeRegisterContextLinux_loongarch64>(
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

NativeRegisterContextLinux_loongarch64::NativeRegisterContextLinux_loongarch64(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread,
    std::unique_ptr<RegisterInfo_loongarch64> register_info_up)
    : NativeRegisterContextRegisterInfo(native_thread,
                                        register_info_up.release()),
      NativeRegisterContextLinux(native_thread) {
  ::memset(&m_fpr, 0, sizeof(m_fpr));
  ::memset(&m_gpr, 0, sizeof(m_gpr));
  ::memset(&m_lsx, 0, sizeof(m_lsx));
  ::memset(&m_lasx, 0, sizeof(m_lasx));

  // Refer to:
  // https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#control-and-status-registers-related-to-watchpoints
  // 14 is just a maximum value, query hardware for actual watchpoint count.
  m_max_hwp_supported = 14;
  m_max_hbp_supported = 14;
  m_refresh_hwdebug_info = true;

  m_gpr_is_valid = false;
  m_fpu_is_valid = false;
  m_lsx_is_valid = false;
  m_lasx_is_valid = false;
}

const RegisterInfo_loongarch64 &
NativeRegisterContextLinux_loongarch64::GetRegisterInfo() const {
  return static_cast<const RegisterInfo_loongarch64 &>(
      NativeRegisterContextRegisterInfo::GetRegisterInfoProvider());
}

uint32_t NativeRegisterContextLinux_loongarch64::GetRegisterSetCount() const {
  return GetRegisterInfo().GetRegisterSetCount();
}

const RegisterSet *NativeRegisterContextLinux_loongarch64::GetRegisterSet(
    uint32_t set_index) const {
  return GetRegisterInfo().GetRegisterSet(set_index);
}

uint32_t NativeRegisterContextLinux_loongarch64::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

Status NativeRegisterContextLinux_loongarch64::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &reg_value) {
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
      status = ReadGPR();
      break;
    case 1:
      status = ReadFPR();
      break;
    case 2:
      status = ReadLSX();
      break;
    case 3:
      status = ReadLASX();
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  auto value = provider.ReadRegister(
      *reg_info,
      {{0, {reinterpret_cast<const uint8_t *>(GetGPRBuffer()), GetGPRSize()}},
       {1, {reinterpret_cast<const uint8_t *>(GetFPRBuffer()), GetFPRSize()}},
       {2, {reinterpret_cast<const uint8_t *>(&m_lsx), sizeof(m_lsx)}},
       {3, {reinterpret_cast<const uint8_t *>(&m_lasx), sizeof(m_lasx)}}});
  if (!value)
    return Status::FromError(value.takeError());
  reg_value = std::move(*value);
  return Status();
}

Status NativeRegisterContextLinux_loongarch64::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  if (!reg_info)
    return Status::FromErrorString("missing register description");
  if (reg_info->kinds[lldb::eRegisterKindLLDB] == gpr_r0_loongarch)
    return Status();
  const auto &provider = GetRegisterInfoProvider();
  auto required = provider.GetRegisterBanks(*reg_info, true);
  if (!required)
    return Status::FromError(required.takeError());
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case 0:
      status = ReadGPR();
      break;
    case 1:
      status = ReadFPR();
      break;
    case 2:
      status = ReadLSX();
      break;
    case 3:
      status = ReadLASX();
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  if (auto error = provider.WriteRegister(
          *reg_info, reg_value,
          {{0, {reinterpret_cast<uint8_t *>(GetGPRBuffer()), GetGPRSize()}},
           {1, {reinterpret_cast<uint8_t *>(GetFPRBuffer()), GetFPRSize()}},
           {2, {reinterpret_cast<uint8_t *>(&m_lsx), sizeof(m_lsx)}},
           {3, {reinterpret_cast<uint8_t *>(&m_lasx), sizeof(m_lasx)}}}))
    return Status::FromError(std::move(error));
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case 0:
      status = WriteGPR();
      break;
    case 1:
      status = WriteFPR();
      break;
    case 2:
      status = WriteLSX();
      break;
    case 3:
      status = WriteLASX();
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  return Status();
}

Status NativeRegisterContextLinux_loongarch64::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error;

  data_sp.reset(new DataBufferHeap(REG_CONTEXT_SIZE, 0));

  error = ReadGPR();
  if (error.Fail())
    return error;

  error = ReadFPR();
  if (error.Fail())
    return error;

  error = ReadLSX();
  if (error.Fail())
    return error;

  error = ReadLASX();
  if (error.Fail())
    return error;

  uint8_t *dst = data_sp->GetBytes();
  ::memcpy(dst, GetGPRBuffer(), GetGPRSize());
  dst += GetGPRSize();
  ::memcpy(dst, GetFPRBuffer(), GetFPRSize());
  dst += GetFPRSize();
  ::memcpy(dst, &m_lsx, sizeof(m_lsx));
  dst += sizeof(m_lsx);
  ::memcpy(dst, &m_lasx, sizeof(m_lasx));

  return error;
}

Status NativeRegisterContextLinux_loongarch64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_loongarch64::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != REG_CONTEXT_SIZE) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_loongarch64::%s data_sp contained "
        "mismatched data size, expected %" PRIu64 ", actual %" PRIu64,
        __FUNCTION__, REG_CONTEXT_SIZE, data_sp->GetByteSize());
    return error;
  }

  const uint8_t *src = data_sp->GetBytes();
  if (src == nullptr) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_loongarch64::%s "
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
  ::memcpy(GetFPRBuffer(), src, GetFPRSize());
  m_fpu_is_valid = true;
  error = WriteFPR();
  if (error.Fail())
    return error;

  // Currently, we assume that LoongArch always support LASX.
  // TODO: check whether LSX/LASX exists.
  src += GetFPRSize();
  ::memcpy(&m_lsx, src, sizeof(m_lsx));
  m_lsx_is_valid = true;
  error = WriteLSX();
  if (error.Fail())
    return error;

  src += sizeof(m_lsx);
  ::memcpy(&m_lasx, src, sizeof(m_lasx));
  m_lasx_is_valid = true;
  error = WriteLASX();
  if (error.Fail())
    return error;

  return error;
}

bool NativeRegisterContextLinux_loongarch64::IsGPR(unsigned reg) const {
  return GetRegisterInfo().GetRegisterSetFromRegisterNumber(reg) ==
         RegisterInfo_loongarch64::GPRegSet;
}

bool NativeRegisterContextLinux_loongarch64::IsFPR(unsigned reg) const {
  return GetRegisterInfo().GetRegisterSetFromRegisterNumber(reg) ==
         RegisterInfo_loongarch64::FPRegSet;
}

bool NativeRegisterContextLinux_loongarch64::IsLSX(unsigned reg) const {
  return GetRegisterInfo().GetRegisterSetFromRegisterNumber(reg) ==
         RegisterInfo_loongarch64::LSXRegSet;
}

bool NativeRegisterContextLinux_loongarch64::IsLASX(unsigned reg) const {
  return GetRegisterInfo().GetRegisterSetFromRegisterNumber(reg) ==
         RegisterInfo_loongarch64::LASXRegSet;
}

Status NativeRegisterContextLinux_loongarch64::ReadGPR() {
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

Status NativeRegisterContextLinux_loongarch64::WriteGPR() {
  Status error = ReadGPR();
  if (error.Fail())
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetGPRBuffer();
  ioVec.iov_len = GetGPRSize();

  m_gpr_is_valid = false;

  return WriteRegisterSet(&ioVec, GetGPRSize(), NT_PRSTATUS);
}

Status NativeRegisterContextLinux_loongarch64::ReadFPR() {
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

Status NativeRegisterContextLinux_loongarch64::WriteFPR() {
  Status error = ReadFPR();
  if (error.Fail())
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetFPRBuffer();
  ioVec.iov_len = GetFPRSize();

  m_fpu_is_valid = false;
  m_lsx_is_valid = false;
  m_lasx_is_valid = false;

  return WriteRegisterSet(&ioVec, GetFPRSize(), NT_FPREGSET);
}

Status NativeRegisterContextLinux_loongarch64::ReadLSX() {
  Status error;

  if (m_lsx_is_valid)
    return error;

  struct iovec ioVec;
  ioVec.iov_base = &m_lsx;
  ioVec.iov_len = sizeof(m_lsx);

  error = ReadRegisterSet(&ioVec, sizeof(m_lsx), NT_LOONGARCH_LSX);

  if (error.Success())
    m_lsx_is_valid = true;

  return error;
}

Status NativeRegisterContextLinux_loongarch64::WriteLSX() {
  Status error = ReadLSX();
  if (error.Fail())
    return error;

  struct iovec ioVec;
  ioVec.iov_base = &m_lsx;
  ioVec.iov_len = sizeof(m_lsx);

  m_fpu_is_valid = false;
  m_lsx_is_valid = false;
  m_lasx_is_valid = false;

  return WriteRegisterSet(&ioVec, sizeof(m_lsx), NT_LOONGARCH_LSX);
}

Status NativeRegisterContextLinux_loongarch64::ReadLASX() {
  Status error;

  if (m_lasx_is_valid)
    return error;

  struct iovec ioVec;
  ioVec.iov_base = &m_lasx;
  ioVec.iov_len = sizeof(m_lasx);

  error = ReadRegisterSet(&ioVec, sizeof(m_lasx), NT_LOONGARCH_LASX);

  if (error.Success())
    m_lasx_is_valid = true;

  return error;
}

Status NativeRegisterContextLinux_loongarch64::WriteLASX() {
  Status error = ReadLASX();
  if (error.Fail())
    return error;

  struct iovec ioVec;
  ioVec.iov_base = &m_lasx;
  ioVec.iov_len = sizeof(m_lasx);

  m_fpu_is_valid = false;
  m_lsx_is_valid = false;
  m_lasx_is_valid = false;

  return WriteRegisterSet(&ioVec, sizeof(m_lasx), NT_LOONGARCH_LASX);
}

void NativeRegisterContextLinux_loongarch64::InvalidateAllRegisters() {
  m_gpr_is_valid = false;
  m_fpu_is_valid = false;
  m_lsx_is_valid = false;
  m_lasx_is_valid = false;
}

std::vector<uint32_t>
NativeRegisterContextLinux_loongarch64::GetExpeditedRegisters(
    ExpeditedRegs expType) const {
  std::vector<uint32_t> expedited_reg_nums =
      NativeRegisterContext::GetExpeditedRegisters(expType);

  return expedited_reg_nums;
}

llvm::Error NativeRegisterContextLinux_loongarch64::ReadHardwareDebugInfo() {
  if (!m_refresh_hwdebug_info)
    return llvm::Error::success();

  ::pid_t tid = m_thread.GetID();

  int regset = NT_LOONGARCH_HW_WATCH;
  struct iovec ioVec;
  struct loongarch_user_watch_state dreg_state;
  Status error;

  ioVec.iov_base = &dreg_state;
  ioVec.iov_len = sizeof(dreg_state);
  error = NativeProcessLinux::PtraceWrapper(PTRACE_GETREGSET, tid, &regset,
                                            &ioVec, ioVec.iov_len);
  if (error.Fail())
    return error.ToError();

  m_max_hwp_supported = dreg_state.dbg_info & 0x3f;

  regset = NT_LOONGARCH_HW_BREAK;
  error = NativeProcessLinux::PtraceWrapper(PTRACE_GETREGSET, tid, &regset,
                                            &ioVec, ioVec.iov_len);
  if (error.Fail())
    return error.ToError();

  m_max_hbp_supported = dreg_state.dbg_info & 0x3f;

  m_refresh_hwdebug_info = false;

  return llvm::Error::success();
}

llvm::Error NativeRegisterContextLinux_loongarch64::WriteHardwareDebugRegs(
    DREGType hwbType) {
  struct iovec ioVec;
  struct loongarch_user_watch_state dreg_state;
  int regset;

  memset(&dreg_state, 0, sizeof(dreg_state));
  ioVec.iov_base = &dreg_state;

  switch (hwbType) {
  case eDREGTypeWATCH:
    regset = NT_LOONGARCH_HW_WATCH;
    ioVec.iov_len = sizeof(dreg_state.dbg_info) +
                    (sizeof(dreg_state.dbg_regs[0]) * m_max_hwp_supported);

    for (uint32_t i = 0; i < m_max_hwp_supported; i++) {
      dreg_state.dbg_regs[i].addr = m_hwp_regs[i].address;
      dreg_state.dbg_regs[i].ctrl = m_hwp_regs[i].control;
    }
    break;
  case eDREGTypeBREAK:
    regset = NT_LOONGARCH_HW_BREAK;
    ioVec.iov_len = sizeof(dreg_state.dbg_info) +
                    (sizeof(dreg_state.dbg_regs[0]) * m_max_hbp_supported);

    for (uint32_t i = 0; i < m_max_hbp_supported; i++) {
      dreg_state.dbg_regs[i].addr = m_hbp_regs[i].address;
      dreg_state.dbg_regs[i].ctrl = m_hbp_regs[i].control;
    }
    break;
  }

  return NativeProcessLinux::PtraceWrapper(PTRACE_SETREGSET, m_thread.GetID(),
                                           &regset, &ioVec, ioVec.iov_len)
      .ToError();
}
#endif // defined(__loongarch__) && __loongarch_grlen == 64
