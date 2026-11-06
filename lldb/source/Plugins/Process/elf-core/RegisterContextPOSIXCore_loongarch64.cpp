//===-- RegisterContextPOSIXCore_loongarch64.cpp --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_loongarch64.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_loongarch64.h"
#include "lldb/Register/RegisterCodec.h"

#include "lldb/Utility/DataBufferHeap.h"

using namespace lldb_private;

std::unique_ptr<RegisterContextCorePOSIX_loongarch64>
RegisterContextCorePOSIX_loongarch64::Create(Thread &thread,
                                             const ArchSpec &arch,
                                             const DataExtractor &gpregset,
                                             llvm::ArrayRef<CoreNote> notes) {
  return std::unique_ptr<RegisterContextCorePOSIX_loongarch64>(
      new RegisterContextCorePOSIX_loongarch64(
          thread,
          std::make_unique<RegisterInfo_loongarch64>(
              arch, CreateLinuxLoongArch64RegisterModel(arch)),
          gpregset, notes));
}

RegisterContextCorePOSIX_loongarch64::RegisterContextCorePOSIX_loongarch64(
    Thread &thread,
    std::unique_ptr<RegisterInfo_loongarch64> register_info,
    const DataExtractor &gpregset, llvm::ArrayRef<CoreNote> notes)
    : RegisterContextCore_loongarch64(thread, std::move(register_info)) {

  m_gpr.SetData(std::make_shared<DataBufferHeap>(gpregset.GetDataStart(),
                                                 gpregset.GetByteSize()));
  m_gpr.SetByteOrder(gpregset.GetByteOrder());

  ArchSpec arch = m_register_info_up->GetTargetArchitecture();
  DataExtractor fpregset = getRegset(notes, arch.GetTriple(), FPR_Desc);
  m_fpr.SetData(std::make_shared<DataBufferHeap>(fpregset.GetDataStart(),
                                                 fpregset.GetByteSize()));
  m_fpr.SetByteOrder(fpregset.GetByteOrder());
}

RegisterContextCorePOSIX_loongarch64::~RegisterContextCorePOSIX_loongarch64() =
    default;

bool RegisterContextCorePOSIX_loongarch64::ReadGPR() { return true; }

bool RegisterContextCorePOSIX_loongarch64::ReadFPR() { return true; }

bool RegisterContextCorePOSIX_loongarch64::WriteGPR() {
  assert(false && "Writing registers is not allowed for core dumps");
  return false;
}

bool RegisterContextCorePOSIX_loongarch64::WriteFPR() {
  assert(false && "Writing registers is not allowed for core dumps");
  return false;
}

bool RegisterContextCorePOSIX_loongarch64::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &value) {
  const auto &provider = *m_register_info_up;
  const auto *reg = provider.GetDescription().Find(reg_info->name);
  if (!reg) return false;
  const RegisterData banks[] = {
      {0, {m_gpr.GetDataStart(), m_gpr.GetByteSize()}},
      {1, {m_fpr.GetDataStart(), m_fpr.GetByteSize()}}};
  auto result = RegisterCodec::Read(provider.GetDescription(),
                                    provider.GetLayout(), reg->id, banks);
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_loongarch64::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &value) {
  return false;
}
