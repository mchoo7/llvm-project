//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_COMMON_REGISTERINFO_POWERPC_H
#define LLDB_REGISTER_COMMON_REGISTERINFO_POWERPC_H
#include "lldb/Register/RegisterInfoProvider.h"
/// ELF PowerPC numbering/value profile, independent of the saved-state layout.
class RegisterInfo_powerpc : public lldb_private::RegisterInfoProvider {
public:
  RegisterInfo_powerpc(const lldb_private::ArchSpec &arch,
                       lldb_private::RegisterModel model)
      : RegisterInfoProvider(arch, std::move(model)) {}
  RegisterInfo_powerpc(const lldb_private::ArchSpec &arch,
                       lldb_private::RegisterLayout layout,
                       uint32_t value_bytes)
      : RegisterInfoProvider(arch, CreateDescription(value_bytes),
                             std::move(layout)) {}
  static std::shared_ptr<const lldb_private::RegisterDescription>
  CreateDescription(uint32_t value_bytes);
};
#endif
