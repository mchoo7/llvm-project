//===-- RegisterContextPOSIXCore_ppc64le.cpp ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_ppc64le.h"

#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"

#include "lldb/Register/Arch/lldb-ppc64le-register-enums.h"
#include "Plugins/Process/elf-core/RegisterUtilities.h"

#include <memory>

using namespace lldb_private;

RegisterContextCorePOSIX_ppc64le::RegisterContextCorePOSIX_ppc64le(
    Thread &thread, RegisterInfoProvider *register_info,
    const DataExtractor &gpregset, llvm::ArrayRef<CoreNote> notes)
    : RegisterContextCore_ppc64le(thread, 0, register_info) {
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

  DataExtractor vmxregset = getRegset(notes, arch.GetTriple(), PPC_VMX_Desc);
  m_vmx_buffer = std::make_shared<DataBufferHeap>(vmxregset.GetDataStart(),
                                                  vmxregset.GetByteSize());
  m_vmx.SetData(m_vmx_buffer);
  m_vmx.SetByteOrder(vmxregset.GetByteOrder());

  DataExtractor vsxregset = getRegset(notes, arch.GetTriple(), PPC_VSX_Desc);
  m_vsx_buffer = std::make_shared<DataBufferHeap>(vsxregset.GetDataStart(),
                                                  vsxregset.GetByteSize());
  m_vsx.SetData(m_vsx_buffer);
  m_vsx.SetByteOrder(vsxregset.GetByteOrder());
}

size_t RegisterContextCorePOSIX_ppc64le::GetFPRSize() const {
  return k_num_fpr_registers_ppc64le * sizeof(uint64_t);
}

size_t RegisterContextCorePOSIX_ppc64le::GetVMXSize() const {
  return (k_num_vmx_registers_ppc64le - 1) * sizeof(uint64_t) * 2 +
         sizeof(uint32_t);
}

size_t RegisterContextCorePOSIX_ppc64le::GetVSXSize() const {
  return k_num_vsx_registers_ppc64le * sizeof(uint64_t) * 2;
}

bool RegisterContextCorePOSIX_ppc64le::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &value) {
  if (!reg_info)
    return false;
  auto result = m_register_info_up->ReadRegister(
      *reg_info, {{0, {m_gpr.GetDataStart(), m_gpr.GetByteSize()}},
                  {1, {m_fpr.GetDataStart(), m_fpr.GetByteSize()}},
                  {2, {m_vmx.GetDataStart(), m_vmx.GetByteSize()}},
                  {3, {m_vsx.GetDataStart(), m_vsx.GetByteSize()}}});
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_ppc64le::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &value) {
  return false;
}
