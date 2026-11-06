//===-- RegisterContextPOSIXCore_x86.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_x86.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/RegisterValue.h"

using namespace lldb_private;

RegisterContextCorePOSIX_x86::RegisterContextCorePOSIX_x86(
    Thread &thread, RegisterInfoProvider *register_info,
    const DataExtractor &gpregset, llvm::ArrayRef<CoreNote> notes)
    : RegisterContextCore_x86(thread, 0, register_info) {
  size_t size, len;

  size = GetGPRSize();
  m_gpregset.reset(new uint8_t[size]);
  len =
      gpregset.ExtractBytes(0, size, lldb::eByteOrderLittle, m_gpregset.get());
  if (len != size)
    m_gpregset.reset();

  DataExtractor fpregset = getRegset(
      notes, register_info->GetTargetArchitecture().GetTriple(), FPR_Desc);
  size = sizeof(FXSAVE);
  m_fpregset.reset(new uint8_t[size]);
  len =
      fpregset.ExtractBytes(0, size, lldb::eByteOrderLittle, m_fpregset.get());
  if (len != size)
    m_fpregset.reset();
}

bool RegisterContextCorePOSIX_x86::ReadGPR() {
  return m_gpregset != nullptr;
}

bool RegisterContextCorePOSIX_x86::ReadFPR() {
  return m_fpregset != nullptr;
}

bool RegisterContextCorePOSIX_x86::WriteGPR() {
  assert(0);
  return false;
}

bool RegisterContextCorePOSIX_x86::WriteFPR() {
  assert(0);
  return false;
}

bool RegisterContextCorePOSIX_x86::ReadRegister(const RegisterInfo *reg_info,
                                                RegisterValue &value) {
  if (!reg_info)
    return false;
  if (llvm::StringRef(reg_info->name) == "ftag") {
    if (!m_fpregset)
      return false;
    const auto *fp = reinterpret_cast<const FXSAVE *>(m_fpregset.get());
    value.SetUInt16(AbridgedToFullTagWord(fp->ftag, fp->fstat, fp->stmm));
    return true;
  }
  auto result = m_register_info_up->ReadRegister(
      *reg_info,
      {{x86_layout::GP, {m_gpregset.get(), m_gpregset ? GetGPRSize() : 0}},
       {x86_layout::FP, {m_fpregset.get(), m_fpregset ? sizeof(FXSAVE) : 0}}});
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_x86::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  return false;
}

bool RegisterContextCorePOSIX_x86::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &value) {
  return false;
}

bool RegisterContextCorePOSIX_x86::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  return false;
}

bool RegisterContextCorePOSIX_x86::HardwareSingleStep(bool enable) {
  return false;
}
