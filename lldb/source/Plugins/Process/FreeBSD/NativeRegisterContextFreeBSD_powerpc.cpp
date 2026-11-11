//===-- NativeRegisterContextFreeBSD_powerpc.cpp --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__powerpc__)

#include <set>

#include "NativeRegisterContextFreeBSD_powerpc.h"

#include "lldb/Host/HostInfo.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Register/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"
#include "llvm/ADT/STLExtras.h"
#include <cstring>

// clang-format off
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/types.h>
// clang-format on

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_freebsd;

static_assert(sizeof(reg) == 37 * sizeof(reg::lr));
static_assert(offsetof(reg, pc) == 36 * sizeof(reg::lr));
static_assert(sizeof(fpreg) == 33 * sizeof(uint64_t));
static_assert(offsetof(fpreg, fpscr) == 32 * sizeof(uint64_t));
static_assert(sizeof(vmxreg) == 528);
static_assert(offsetof(vmxreg, vrsave) == 520);
static_assert(offsetof(vmxreg, vscr) == 524);

NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &arch, NativeThreadFreeBSD &thread) {
  bool has_vmx = false, has_vsx = false;
  if (arch.GetMachine() == llvm::Triple::ppc64le) {
    vmxreg vmx{};
    has_vmx =
        NativeProcessFreeBSD::PtraceWrapper(PT_GETVRREGS, thread.GetID(), &vmx)
            .Success();
    freebsd_powerpc::VSX vsx{};
    has_vsx = has_vmx && NativeProcessFreeBSD::PtraceWrapper(
                             PT_GETVSRREGS, thread.GetID(), &vsx)
                             .Success();
  }
  return new NativeRegisterContextFreeBSD_powerpc(arch, thread, has_vmx,
                                                  has_vsx);
}

static RegisterLayout CreateRegisterLayout(const ArchSpec &arch, bool has_vmx,
                                           bool has_vsx) {
  assert((arch.GetMachine() == llvm::Triple::ppc ||
          arch.GetMachine() == llvm::Triple::ppc64le) &&
         "unsupported FreeBSD PowerPC architecture");
  // PT_GETREGS uses the tracer's ABI, including when tracing a 32-bit inferior.
  auto layout = HostInfo::GetArchitecture().GetAddressByteSize() == 4
                    ? CreateFreeBSDPowerPC32RegisterLayout(arch)
                    : CreateFreeBSDPowerPC64RegisterLayout(arch, has_vsx);
  auto previous = layout.GetDescription();
  std::vector<RegisterGroup> groups;
  std::set<RegisterID> visible;
  for (const auto &input : previous->GetGroups()) {
    RegisterGroup group{input.name, input.short_name, {}};
    for (RegisterID id : input.registers) {
      const auto *location = layout.Find(id);
      if (!location || !llvm::all_of(location->pieces, [&](const auto &piece) {
            return piece.bank < 2 || (piece.bank == 2 && has_vmx) ||
                   (piece.bank == 3 && has_vsx);
          }))
        continue;
      group.registers.push_back(id);
      visible.insert(id);
    }
    if (!group.registers.empty())
      groups.push_back(std::move(group));
  }
  auto description = llvm::cantFail(RegisterDescription::Create(
      {previous->GetRegisters().begin(), previous->GetRegisters().end()},
      std::move(groups),
      {previous->GetOwnedTypes().begin(), previous->GetOwnedTypes().end()}));
  std::vector<RegisterID> order;
  for (RegisterID id : previous->GetUserRegisters())
    if (visible.count(id))
      order.push_back(id);
  auto presentation = llvm::cantFail(description.WithUserRegisters(order));
  return llvm::cantFail(RegisterLayout::Create(
      std::make_shared<RegisterDescription>(std::move(presentation)),
      std::move(layout)));
}

NativeRegisterContextFreeBSD_powerpc::NativeRegisterContextFreeBSD_powerpc(
    const ArchSpec &arch, NativeThreadFreeBSD &thread, bool has_vmx,
    bool has_vsx)
    : NativeRegisterContext(thread, arch,
                            CreateRegisterLayout(arch, has_vmx, has_vsx)),
      m_has_vmx(has_vmx), m_has_vsx(has_vsx) {}

bool NativeRegisterContextFreeBSD_powerpc::HasRegisterSet(
    RegSetKind set) const {
  return set == GPRegSet || set == FPRegSet ||
         (set == VMXRegSet && m_has_vmx) || (set == VSXRegSet && m_has_vsx);
}

std::array<MutableRegisterData, 4>
NativeRegisterContextFreeBSD_powerpc::GetRegisterBanks() {
  return {{{0, {reinterpret_cast<uint8_t *>(&m_gpr), sizeof(m_gpr)}},
           {1, {reinterpret_cast<uint8_t *>(&m_fpr), sizeof(m_fpr)}},
           {2, {reinterpret_cast<uint8_t *>(&m_vmx), sizeof(m_vmx)}},
           {3, {reinterpret_cast<uint8_t *>(&m_vsx), sizeof(m_vsx)}}}};
}

Status NativeRegisterContextFreeBSD_powerpc::ReadRegisterSet(RegSetKind set) {
  switch (set) {
  case GPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETREGS, m_thread.GetID(),
                                               &m_gpr);
  case FPRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETFPREGS, m_thread.GetID(),
                                               &m_fpr);
  case VMXRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETVRREGS, m_thread.GetID(),
                                               &m_vmx);
  case VSXRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_GETVSRREGS, m_thread.GetID(),
                                               &m_vsx);
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
  case VMXRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETVRREGS, m_thread.GetID(),
                                               &m_vmx);
  case VSXRegSet:
    return NativeProcessFreeBSD::PtraceWrapper(PT_SETVSRREGS, m_thread.GetID(),
                                               &m_vsx);
  }
  llvm_unreachable("NativeRegisterContextFreeBSD_powerpc::WriteRegisterSet");
}

llvm::Expected<RegisterValue>
NativeRegisterContextFreeBSD_powerpc::ReadRegister(RegisterID id) {
  auto required = GetLayout().GetRequiredBanks(id);
  if (!required)
    return required.takeError();
  for (RegisterBankID bank : *required) {
    auto set = static_cast<RegSetKind>(bank);
    if (!HasRegisterSet(set))
      return llvm::createStringError("unsupported register bank");
    if (Status error = ReadRegisterSet(set); error.Fail())
      return error.ToError();
  }
  auto banks = GetRegisterBanks();
  std::vector<RegisterData> data;
  for (const auto &bank : banks)
    data.push_back({bank.bank, bank.bytes});
  return ReadBankRegister(id, data);
}

llvm::Error NativeRegisterContextFreeBSD_powerpc::WriteRegister(
    RegisterID id, const RegisterValue &value) {
  auto required = GetLayout().GetRequiredBanks(id, true);
  if (!required)
    return required.takeError();
  for (RegisterBankID bank : *required) {
    auto set = static_cast<RegSetKind>(bank);
    if (!HasRegisterSet(set))
      return llvm::createStringError("unsupported register bank");
    if (Status error = ReadRegisterSet(set); error.Fail())
      return error.ToError();
  }
  if (auto error = WriteBankRegister(id, value, GetRegisterBanks()))
    return error;
  for (RegisterBankID bank : *required)
    if (Status error = WriteRegisterSet(static_cast<RegSetKind>(bank));
        error.Fail())
      return error.ToError();
  return llvm::Error::success();
}

Status NativeRegisterContextFreeBSD_powerpc::ReadAllRegisterValues(
    WritableDataBufferSP &data) {
  auto banks = GetRegisterBanks();
  size_t size = 0;
  for (const auto &bank : banks) {
    auto set = static_cast<RegSetKind>(bank.bank);
    if (!HasRegisterSet(set))
      continue;
    if (Status error = ReadRegisterSet(set); error.Fail())
      return error;
    size += bank.bytes.size();
  }
  data = std::make_shared<DataBufferHeap>(size, 0);
  size_t offset = 0;
  for (const auto &bank : banks) {
    if (!HasRegisterSet(static_cast<RegSetKind>(bank.bank)))
      continue;
    std::memcpy(data->GetBytes() + offset, bank.bytes.data(),
                bank.bytes.size());
    offset += bank.bytes.size();
  }
  return Status();
}

Status NativeRegisterContextFreeBSD_powerpc::WriteAllRegisterValues(
    const DataBufferSP &data) {
  auto banks = GetRegisterBanks();
  size_t size = 0;
  for (const auto &bank : banks)
    if (HasRegisterSet(static_cast<RegSetKind>(bank.bank)))
      size += bank.bytes.size();
  if (!data || data->GetByteSize() != size)
    return Status::FromErrorString("invalid private register checkpoint");
  size_t offset = 0;
  for (const auto &bank : banks) {
    auto set = static_cast<RegSetKind>(bank.bank);
    if (!HasRegisterSet(set))
      continue;
    std::memcpy(bank.bytes.data(), data->GetBytes() + offset,
                bank.bytes.size());
    offset += bank.bytes.size();
    if (Status error = WriteRegisterSet(set); error.Fail())
      return error;
  }
  return Status();
}

llvm::Error NativeRegisterContextFreeBSD_powerpc::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  return llvm::Error::success();
}

#endif // defined (__powerpc__)
