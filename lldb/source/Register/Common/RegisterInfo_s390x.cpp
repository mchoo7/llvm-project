//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_s390x.h"
#include "lldb/Register/Arch/lldb-s390x-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-s390x-register-enums.h"
using namespace lldb_private;

std::shared_ptr<const RegisterDescription>
RegisterInfo_s390x::CreateDescription() {
#include "Register/Arch/RegisterDescriptions_s390x.inc"
  static const auto description = [] {
    auto imported = llvm::cantFail(RegisterDescription::FromLegacy(values));
    RegisterGroup gpr{"General Purpose Registers", "gpr", {}};
    RegisterGroup fpr{"Floating Point Registers", "fpr", {}};
    for (const auto &info : values) {
      auto id = info.kinds[lldb::eRegisterKindLLDB];
      (id <= k_last_gpr_s390x ? gpr : fpr).registers.push_back(id);
    }
    return std::make_shared<RegisterDescription>(
        llvm::cantFail(RegisterDescription::Create(
            std::vector<RegisterDescriptor>(imported.GetRegisters().begin(),
                                            imported.GetRegisters().end()),
            {std::move(gpr), std::move(fpr)})));
  }();
  return description;
}
