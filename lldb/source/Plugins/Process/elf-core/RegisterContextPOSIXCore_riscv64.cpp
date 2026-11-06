//===-- RegisterContextPOSIXCore_riscv64.cpp ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_riscv64.h"

#include "lldb/Register/Layouts/Linux/RegisterModelLinux_riscv64.h"
#include "lldb/Register/RegisterCodec.h"
#include "lldb/Utility/DataBufferHeap.h"

using namespace lldb_private;

std::unique_ptr<RegisterContextCorePOSIX_riscv64>
RegisterContextCorePOSIX_riscv64::Create(Thread &thread, const ArchSpec &arch,
                                         const DataExtractor &gpregset,
                                         llvm::ArrayRef<CoreNote> notes) {
  Flags opt_regsets = RegisterInfo_riscv64::eRegsetMaskDefault;

  DataExtractor fpregset = getRegset(notes, arch.GetTriple(), FPR_Desc);
  if (fpregset.GetByteSize() >= sizeof(uint64_t)) {
    opt_regsets.Set(RegisterInfo_riscv64::eRegsetMaskFP);
  }

  return std::unique_ptr<RegisterContextCorePOSIX_riscv64>(
      new RegisterContextCorePOSIX_riscv64(
          thread,
          std::make_unique<RegisterInfo_riscv64>(
              arch, opt_regsets,
              CreateLinuxRISCV64RegisterModel(arch, opt_regsets)),
          gpregset, notes));
}

RegisterContextCorePOSIX_riscv64::RegisterContextCorePOSIX_riscv64(
    Thread &thread, std::unique_ptr<RegisterInfo_riscv64> register_info,
    const DataExtractor &gpregset, llvm::ArrayRef<CoreNote> notes)
    : RegisterContextCore_riscv64(thread, std::move(register_info)) {

  m_gpr.SetData(std::make_shared<DataBufferHeap>(gpregset.GetDataStart(),
                                                 gpregset.GetByteSize()));
  m_gpr.SetByteOrder(gpregset.GetByteOrder());

  if (m_register_info_up->IsFPPresent()) {
    ArchSpec arch = m_register_info_up->GetTargetArchitecture();
    m_fpr = getRegset(notes, arch.GetTriple(), FPR_Desc);
  }
}

RegisterContextCorePOSIX_riscv64::~RegisterContextCorePOSIX_riscv64() = default;

bool RegisterContextCorePOSIX_riscv64::ReadGPR() { return true; }

bool RegisterContextCorePOSIX_riscv64::ReadFPR() { return true; }

bool RegisterContextCorePOSIX_riscv64::WriteGPR() {
  assert(false && "Writing registers is not allowed for core dumps");
  return false;
}

bool RegisterContextCorePOSIX_riscv64::WriteFPR() {
  assert(false && "Writing registers is not allowed for core dumps");
  return false;
}

bool RegisterContextCorePOSIX_riscv64::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &value) {
  const auto &description = m_register_info_up->GetDescription();
  const auto *reg = description.Find(reg_info->name);
  if (!reg)
    return false;
  std::vector<RegisterData> banks;
  banks.push_back({0, {m_gpr.GetDataStart(), m_gpr.GetByteSize()}});
  if (m_register_info_up->IsFPPresent())
    banks.push_back({1, {m_fpr.GetDataStart(), m_fpr.GetByteSize()}});
  auto result = RegisterCodec::Read(
      description, m_register_info_up->GetLayout(), reg->id, banks);
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_riscv64::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &value) {
  return false;
}
