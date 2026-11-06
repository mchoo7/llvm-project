//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/Linux/RegisterModelLinux_arm.h"
#include "lldb/Register/Arch/lldb-arm-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_arm.h"
#include <cstddef>
using namespace lldb_private;
RegisterModel lldb_private::CreateLinuxArmRegisterModel(const ArchSpec &arch,
                                                        bool tls) {
  auto description = RegisterInfo_arm::CreateDescription(tls);
  RegisterLayout layout(arch.GetByteOrder());
  llvm::cantFail(layout.AddBank(0, sizeof(linux_arm::GPR)));
  llvm::cantFail(layout.AddBank(1, sizeof(linux_arm::FPU)));
  if (tls)
    llvm::cantFail(layout.AddBank(2, sizeof(linux_arm::TLS)));
  for (const auto &reg : description->GetRegisters()) {
    RegisterBankID bank = 0;
    uint32_t offset = 0;
    if (reg.id <= gpr_cpsr_arm)
      offset = 4 * reg.id;
    else if (reg.id <= fpu_q15_arm) {
      bank = 1;

      if (reg.id == fpu_fpscr_arm)
        offset = offsetof(linux_arm::FPU, fpscr);
      else if (reg.id < fpu_fpscr_arm)
        offset = 4 * (reg.id - fpu_s0_arm);
      else if (reg.id < fpu_q0_arm)
        offset = 8 * (reg.id - fpu_d0_arm);
      else
        offset = 16 * (reg.id - fpu_q0_arm);
    } else {
      bank = 2;
    }
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({bank, offset, reg.byte_size});

    llvm::cantFail(layout.Add(reg.id, std::move(location)));
  }
  llvm::cantFail(layout.Validate(*description));
  return {std::move(description), std::move(layout)};
}
