//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_riscv64.h"
#include "lldb/Register/Arch/lldb-riscv64-register-enums.h"
#include "lldb/Register/Descriptions/RegisterDescription_riscv64.h"
#include "lldb/Utility/ArchSpec.h"

#include <cstddef>

namespace reg_ids = lldb_private::registers::riscv64::id;

using namespace lldb_private;

RegisterLayoutFreeBSD_riscv64::RegisterLayoutFreeBSD_riscv64(
    const ArchSpec &arch, bool has_fp) {
  auto description = RegisterDescription_riscv64::GetShared(
      {Flags(has_fp ? RegisterDescription_riscv64::eRegsetMaskFP : 0)});
  llvm::cantFail(AddBank(0, sizeof(GPR)));

  if (has_fp)
    llvm::cantFail(AddBank(1, sizeof(FPR)));

  const auto get_location =
      [&](const RegisterDescriptor &reg) -> std::optional<RegisterLocation> {
    const RegisterID id = reg.id;
    if (has_fp && id >= reg_ids::fpr_f0 && id <= reg_ids::fpr_f31) {
      // Each slot reserves 128 bits; the D-extension value uses 64.
      return RegisterLocation::StoredAt(
          1, offsetof(FPR, x) + (id - reg_ids::fpr_f0) * 16, 8);
    }
    if (has_fp && id == reg_ids::fpr_fcsr)
      return RegisterLocation::StoredAt(1, offsetof(FPR, fcsr), 4);

    uint64_t offset;
    switch (id) {
    case reg_ids::gpr_ra:
      offset = offsetof(GPR, ra);
      break;
    case reg_ids::gpr_sp:
      offset = offsetof(GPR, sp);
      break;
    case reg_ids::gpr_gp:
      offset = offsetof(GPR, gp);
      break;
    case reg_ids::gpr_tp:
      offset = offsetof(GPR, tp);
      break;
    case reg_ids::gpr_pc:
      offset = offsetof(GPR, sepc);
      break;
    case reg_ids::gpr_fp:
      offset = offsetof(GPR, s);
      break;
    case reg_ids::gpr_s1:
      offset = offsetof(GPR, s) + 8;
      break;
    default:
      if (id >= reg_ids::gpr_t0 && id <= reg_ids::gpr_t2)
        offset = offsetof(GPR, t) + (id - reg_ids::gpr_t0) * 8;
      else if (id >= reg_ids::gpr_t3 && id <= reg_ids::gpr_t6)
        offset = offsetof(GPR, t) + (3 + id - reg_ids::gpr_t3) * 8;
      else if (id >= reg_ids::gpr_s2 && id <= reg_ids::gpr_s11)
        offset = offsetof(GPR, s) + (2 + id - reg_ids::gpr_s2) * 8;
      else if (id >= reg_ids::gpr_a0 && id <= reg_ids::gpr_a7)
        offset = offsetof(GPR, a) + (id - reg_ids::gpr_a0) * 8;
      else
        // x0 is an architectural constant and has no saved slot.
        return std::nullopt;
    }
    return RegisterLocation::StoredAt(0, offset, 8);
  };

  llvm::cantFail(AddRegisterLocations(*description, get_location));

  llvm::cantFail(Finalize(std::move(description), arch.GetByteOrder()));
}
