//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_COMMON_REGISTERINFO_RISCV64_H
#define LLDB_REGISTER_COMMON_REGISTERINFO_RISCV64_H

#include "lldb/Register/RegisterInfoProvider.h"
#include "lldb/Utility/Flags.h"

class RegisterInfo_riscv64 : public lldb_private::RegisterInfoProvider {
public:
  RegisterInfo_riscv64(const lldb_private::ArchSpec &arch,
                       lldb_private::Flags features,
                       lldb_private::RegisterModel model)
      : RegisterInfoProvider(arch, std::move(model)), m_features(features) {}
  enum { GPRegSet = 0, FPRegSet = 1 };
  enum { eRegsetMaskDefault = 0, eRegsetMaskFP = 1, eRegsetMaskAll = -1 };

  RegisterInfo_riscv64(const lldb_private::ArchSpec &arch,
                       lldb_private::Flags features,
                       lldb_private::RegisterLayout layout);

  static std::shared_ptr<const lldb_private::RegisterDescription>
  CreateDescription(lldb_private::Flags features);

  bool IsFPPresent() const { return m_features.AnySet(eRegsetMaskFP); }
  bool IsFPReg(unsigned reg) const {
    return GetRegisterSetFromRegisterNumber(reg) == FPRegSet;
  }

private:
  lldb_private::Flags m_features;
};

#endif
