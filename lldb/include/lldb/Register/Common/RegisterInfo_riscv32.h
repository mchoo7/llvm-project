//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_COMMON_REGISTERINFO_RISCV32_H
#define LLDB_REGISTER_COMMON_REGISTERINFO_RISCV32_H
#include "lldb/Register/RegisterInfoProvider.h"
#include "lldb/Utility/Flags.h"
#include "llvm/ADT/SmallVector.h"

class RegisterInfo_riscv32 : public lldb_private::RegisterInfoProvider {
public:
  RegisterInfo_riscv32(const lldb_private::ArchSpec &arch,
                       lldb_private::Flags features,
                       lldb_private::RegisterModel model);
  enum { eRegsetMaskDefault = 0, eRegsetMaskFP = 1, eRegsetMaskAll = -1 };
  RegisterInfo_riscv32(const lldb_private::ArchSpec &arch,
                       lldb_private::Flags features,
                       lldb_private::RegisterLayout layout);
  static std::shared_ptr<const lldb_private::RegisterDescription>
  CreateDescription();
  bool IsFPPresent() const { return m_features.AnySet(eRegsetMaskFP); }

  static void
  BuildCSRegInfos(llvm::ArrayRef<std::string> features,
                  llvm::SmallVectorImpl<lldb_private::RegisterInfo> &infos);

private:
  static void
  ConfigureCSRegInfos(llvm::StringRef feature,
                      llvm::SmallVectorImpl<lldb_private::RegisterInfo> &infos);
  lldb_private::Flags m_features;
};
#endif
