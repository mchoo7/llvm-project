//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_arm.h"
#include "lldb/Register/Arch/lldb-arm-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-arm-register-enums.h"
using namespace lldb_private;
#include "Register/Arch/RegisterDescriptions_arm.inc"
std::shared_ptr<const RegisterDescription>
RegisterInfo_arm::CreateDescription(bool tls) {
  auto make = [](bool tls) {
    const size_t count = tls ? tls_tpidruro_arm + 1 : fpu_q15_arm + 1;
    auto imported = llvm::cantFail(RegisterDescription::FromLegacy(
        llvm::ArrayRef(g_register_infos_arm).take_front(count)));
    std::vector<RegisterDescriptor> regs(imported.GetRegisters().begin(),
                                         imported.GetRegisters().end());
    std::vector<RegisterGroup> groups = {
        {"General Purpose Registers", "gpr", {}},
        {"Floating Point Registers", "fpu", {}}};
    if (tls)
      groups.push_back({"Thread Local Storage Registers", "tls", {}});
    for (auto &reg : regs) {
      if (reg.id >= fpu_s0_arm && reg.id <= fpu_s31_arm)
        reg.value_byte_offset = ((reg.id - fpu_s0_arm) % 4) * 4;
      if (reg.id >= fpu_d0_arm && reg.id <= fpu_d31_arm)
        reg.value_byte_offset = ((reg.id - fpu_d0_arm) % 2) * 8;
      groups[reg.id <= gpr_cpsr_arm  ? GPRegSet
             : reg.id <= fpu_q15_arm ? FPRegSet
                                     : TLSRegSet]
          .registers.push_back(reg.id);
    }
    return std::make_shared<RegisterDescription>(llvm::cantFail(
        RegisterDescription::Create(std::move(regs), std::move(groups))));
  };
  static const auto base = make(false);
  static const auto with_tls = make(true);
  return tls ? with_tls : base;
}
