//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_loongarch64.h"
#include "lldb/Register/Arch/lldb-loongarch-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-loongarch-register-enums.h"
#include "lldb/lldb-private-types.h"
#include "llvm/Support/Compiler.h"
#include <cstddef>
#include <iterator>
using namespace lldb_private;

#define GPR_OFFSET(idx) 0
#define FPR_OFFSET(idx) 0
#define FCC_OFFSET(idx) 0
#define FCSR_OFFSET 0
#define LSX_OFFSET(idx) 0
#define LASX_OFFSET(idx) 0
#define DECLARE_REGISTER_INFOS_LOONGARCH64_STRUCT
#include "Register/Arch/RegisterDescriptions_loongarch64.inc"
#undef DECLARE_REGISTER_INFOS_LOONGARCH64_STRUCT
#undef GPR_OFFSET
#undef FPR_OFFSET
#undef FCC_OFFSET
#undef FCSR_OFFSET
#undef LSX_OFFSET
#undef LASX_OFFSET

std::shared_ptr<const RegisterDescription>
RegisterInfo_loongarch64::CreateDescription() {
  static const auto description = [] {
    auto values = llvm::cantFail(
        RegisterDescription::FromLegacy(g_register_infos_loongarch64));
    std::vector<RegisterDescriptor> registers(values.GetRegisters().begin(),
                                              values.GetRegisters().end());
    std::vector<RegisterGroup> groups = {
        {"General Purpose Registers", "gpr", {}},
        {"Floating Point Registers", "fpr", {}},
        {"LSX Vector Registers", "lsx", {}},
        {"LASX Vector Registers", "lasx", {}}};
    for (auto &reg : registers) {
      if (reg.id == gpr_r0_loongarch)
        reg.constant_value.resize(reg.byte_size, 0);
      size_t group = reg.id <= gpr_last_loongarch   ? GPRegSet
                     : reg.id <= fpr_last_loongarch ? FPRegSet
                     : reg.id <= lsx_last_loongarch ? LSXRegSet
                                                    : LASXRegSet;
      groups[group].registers.push_back(reg.id);
    }
    return std::make_shared<RegisterDescription>(llvm::cantFail(
        RegisterDescription::Create(std::move(registers), std::move(groups))));
  }();
  return description;
}
