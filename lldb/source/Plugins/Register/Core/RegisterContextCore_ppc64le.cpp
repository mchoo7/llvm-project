//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Endian.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Scalar.h"
#include "llvm/Support/Compiler.h"

#include "RegisterContextCore_ppc64le.h"

using namespace lldb_private;
using namespace lldb;

bool RegisterContextCore_ppc64le::IsGPR(unsigned reg) {
  return m_register_info_up->GetRegisterSetFromRegisterNumber(reg) == 0;
}

bool RegisterContextCore_ppc64le::IsFPR(unsigned reg) {
  return m_register_info_up->GetRegisterSetFromRegisterNumber(reg) == 1;
}

bool RegisterContextCore_ppc64le::IsVMX(unsigned reg) {
  return m_register_info_up->GetRegisterSetFromRegisterNumber(reg) == 2;
}

bool RegisterContextCore_ppc64le::IsVSX(unsigned reg) {
  return m_register_info_up->GetRegisterSetFromRegisterNumber(reg) == 3;
}

RegisterContextCore_ppc64le::RegisterContextCore_ppc64le(
    Thread &thread, uint32_t concrete_frame_idx,
    RegisterInfoProvider *register_info)
    : RegisterContext(thread, concrete_frame_idx) {
  m_register_info_up.reset(register_info);
}

void RegisterContextCore_ppc64le::InvalidateAllRegisters() {}

unsigned RegisterContextCore_ppc64le::GetRegisterSize(unsigned reg) {
  const auto *info = m_register_info_up->GetRegisterInfoByNumber(reg);
  assert(info && "unknown register number");
  return info->byte_size;
}

size_t RegisterContextCore_ppc64le::GetRegisterCount() {
  return m_register_info_up->GetRegisterCount();
}

size_t RegisterContextCore_ppc64le::GetGPRSize() {
  return m_register_info_up->GetGPRSize();
}

const RegisterInfo *RegisterContextCore_ppc64le::GetRegisterInfo() {
  // Commonly, this method is overridden and g_register_infos is copied and
  // specialized. So, use GetRegisterInfo() rather than g_register_infos in
  // this scope.
  return m_register_info_up->GetRegisterInfo();
}

const RegisterInfo *
RegisterContextCore_ppc64le::GetRegisterInfoAtIndex(size_t reg) {
  if (reg < GetRegisterCount())
    return &GetRegisterInfo()[reg];
  else
    return nullptr;
}

size_t RegisterContextCore_ppc64le::GetRegisterSetCount() {
  return m_register_info_up->GetRegisterSetCount();
}

const RegisterSet *RegisterContextCore_ppc64le::GetRegisterSet(size_t set) {
  return IsRegisterSetAvailable(set) ? m_register_info_up->GetRegisterSet(set)
                                     : nullptr;
}

const char *RegisterContextCore_ppc64le::GetRegisterName(unsigned reg) {
  const auto *info = m_register_info_up->GetRegisterInfoByNumber(reg);
  assert(info && "unknown register number");
  return info->name;
}

bool RegisterContextCore_ppc64le::IsRegisterSetAvailable(size_t set_index) {
  return set_index < m_register_info_up->GetRegisterSetCount();
}
