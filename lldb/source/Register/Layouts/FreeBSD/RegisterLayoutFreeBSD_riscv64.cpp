//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_riscv64.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_riscv64.h"
#include "lldb/Utility/ArchSpec.h"
#include <cstddef>


namespace reg_ids = lldb_private::registers::riscv::id;
using namespace lldb_private;
using namespace lldb_private::freebsd_riscv64;

RegisterLayout
lldb_private::CreateFreeBSDRISCV64RegisterLayout(const ArchSpec &arch,
                                                 bool has_fp) {
  auto description = RegisterInfo_riscv64::CreateDescription(
      Flags(has_fp ? RegisterInfo_riscv64::eRegsetMaskFP : 0));
  RegisterLayout layout(arch.GetByteOrder());
  llvm::cantFail(layout.AddBank(0, sizeof(GPR)));
  auto add = [&](RegisterID id, RegisterBankID bank, size_t offset,
                 uint32_t size) {
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({bank, offset, size});
    llvm::cantFail(layout.Add(id, std::move(location)));
  };
  add(reg_ids::gpr_ra, 0, offsetof(GPR, ra), 8);
  add(reg_ids::gpr_sp, 0, offsetof(GPR, sp), 8);
  add(reg_ids::gpr_gp, 0, offsetof(GPR, gp), 8);
  add(reg_ids::gpr_tp, 0, offsetof(GPR, tp), 8);
  const RegisterID temporaries[] = {
      reg_ids::gpr_t0, reg_ids::gpr_t1, reg_ids::gpr_t2, reg_ids::gpr_t3,
      reg_ids::gpr_t4, reg_ids::gpr_t5, reg_ids::gpr_t6};
  for (size_t i = 0; i != 7; ++i)
    add(temporaries[i], 0, offsetof(GPR, t) + i * 8, 8);
  const RegisterID saved[] = {
      reg_ids::gpr_fp, reg_ids::gpr_s1, reg_ids::gpr_s2,  reg_ids::gpr_s3,
      reg_ids::gpr_s4, reg_ids::gpr_s5, reg_ids::gpr_s6,  reg_ids::gpr_s7,
      reg_ids::gpr_s8, reg_ids::gpr_s9, reg_ids::gpr_s10, reg_ids::gpr_s11};
  for (size_t i = 0; i != 12; ++i)
    add(saved[i], 0, offsetof(GPR, s) + i * 8, 8);
  for (size_t i = 0; i != 8; ++i)
    add(reg_ids::gpr_a0 + i, 0, offsetof(GPR, a) + i * 8, 8);
  add(reg_ids::gpr_pc, 0, offsetof(GPR, sepc), 8);
  // x0 is an architectural constant and has no kernel storage slot.
  if (has_fp) {
    llvm::cantFail(layout.AddBank(1, sizeof(FPR)));
    // Each FreeBSD slot reserves 128 bits; the D-extension value uses 64.
    for (size_t i = 0; i != 32; ++i)
      add(reg_ids::fpr_f0 + i, 1, offsetof(FPR, x) + i * 16, 8);
    add(reg_ids::fpr_fcsr, 1, offsetof(FPR, fcsr), 4);
  }
  return llvm::cantFail(
      RegisterLayout::Create(std::move(description), std::move(layout)));
}
