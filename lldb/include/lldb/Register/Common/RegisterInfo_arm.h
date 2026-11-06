//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_COMMON_REGISTERINFO_ARM_H
#define LLDB_REGISTER_COMMON_REGISTERINFO_ARM_H
#include "lldb/Register/RegisterInfoProvider.h"
class RegisterInfo_arm : public lldb_private::RegisterInfoProvider {
public:
  RegisterInfo_arm(const lldb_private::ArchSpec &arch,
                   lldb_private::RegisterModel model)
      : RegisterInfoProvider(arch, std::move(model)) {}
  enum { GPRegSet = 0, FPRegSet, TLSRegSet };
  RegisterInfo_arm(const lldb_private::ArchSpec &arch,
                   lldb_private::RegisterLayout layout, bool tls = false)
      : RegisterInfoProvider(arch, CreateDescription(tls), std::move(layout)) {}
  static std::shared_ptr<const lldb_private::RegisterDescription>
  CreateDescription(bool tls = false);
};
#endif
