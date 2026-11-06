//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_COMMON_REGISTERINFO_PPC64_H
#define LLDB_REGISTER_COMMON_REGISTERINFO_PPC64_H
#include "lldb/Register/RegisterInfoProvider.h"
class RegisterInfo_ppc64 : public lldb_private::RegisterInfoProvider {
public:
  RegisterInfo_ppc64(const lldb_private::ArchSpec &arch,
                     lldb_private::RegisterModel model)
      : RegisterInfoProvider(arch, std::move(model)) {}
  RegisterInfo_ppc64(const lldb_private::ArchSpec &arch,
                     lldb_private::RegisterLayout layout);
  static std::shared_ptr<const lldb_private::RegisterDescription>
  CreateDescription(const lldb_private::ArchSpec &arch);
};
#endif
