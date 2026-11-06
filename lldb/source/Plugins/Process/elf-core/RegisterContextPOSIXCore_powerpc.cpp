//===-- RegisterContextPOSIXCore_powerpc.cpp ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_powerpc.h"

#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"

#include <memory>

using namespace lldb_private;

RegisterContextCorePOSIX_powerpc::RegisterContextCorePOSIX_powerpc(
    Thread &thread, RegisterInfoProvider *register_info,
    const DataExtractor &gpregset, llvm::ArrayRef<CoreNote> notes)
    : RegisterContextCore_powerpc(thread, 0, register_info) {
  m_gpr_buffer = std::make_shared<DataBufferHeap>(gpregset.GetDataStart(),
                                                  gpregset.GetByteSize());
  m_gpr.SetData(m_gpr_buffer);
  m_gpr.SetByteOrder(gpregset.GetByteOrder());

  ArchSpec arch = register_info->GetTargetArchitecture();
  DataExtractor fpregset = getRegset(notes, arch.GetTriple(), FPR_Desc);
  m_fpr_buffer = std::make_shared<DataBufferHeap>(fpregset.GetDataStart(),
                                                  fpregset.GetByteSize());
  m_fpr.SetData(m_fpr_buffer);
  m_fpr.SetByteOrder(fpregset.GetByteOrder());

  DataExtractor vregset = getRegset(notes, arch.GetTriple(), PPC_VMX_Desc);
  m_vec_buffer = std::make_shared<DataBufferHeap>(vregset.GetDataStart(),
                                                  vregset.GetByteSize());
  m_vec.SetData(m_vec_buffer);
  m_vec.SetByteOrder(vregset.GetByteOrder());
}

RegisterContextCorePOSIX_powerpc::~RegisterContextCorePOSIX_powerpc() = default;

bool RegisterContextCorePOSIX_powerpc::ReadGPR() { return true; }

bool RegisterContextCorePOSIX_powerpc::ReadFPR() { return true; }

bool RegisterContextCorePOSIX_powerpc::ReadVMX() { return true; }

bool RegisterContextCorePOSIX_powerpc::WriteGPR() {
  assert(0);
  return false;
}

bool RegisterContextCorePOSIX_powerpc::WriteFPR() {
  assert(0);
  return false;
}

bool RegisterContextCorePOSIX_powerpc::WriteVMX() {
  assert(0);
  return false;
}

bool RegisterContextCorePOSIX_powerpc::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &value) {
  if (!reg_info)
    return false;
  auto result = m_register_info_up->ReadRegister(
      *reg_info, {{0, {m_gpr.GetDataStart(), m_gpr.GetByteSize()}},
                  {1, {m_fpr.GetDataStart(), m_fpr.GetByteSize()}},
                  {2, {m_vec.GetDataStart(), m_vec.GetByteSize()}}});
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_powerpc::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  return false;
}

bool RegisterContextCorePOSIX_powerpc::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &value) {
  return false;
}

bool RegisterContextCorePOSIX_powerpc::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  return false;
}

bool RegisterContextCorePOSIX_powerpc::HardwareSingleStep(bool enable) {
  return false;
}
