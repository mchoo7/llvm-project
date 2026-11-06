//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/Linux/RegisterModelLinux_riscv64.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include <iterator>

using namespace lldb_private;

static RegisterLayout CreateLayout(const RegisterDescription &description,
                                   lldb::ByteOrder byte_order) {
  RegisterLayout layout(byte_order);
  llvm::cantFail(layout.AddBank(0, sizeof(linux_riscv64::GPR)));
  auto add = [&](RegisterID id, RegisterBankID bank, uint32_t offset,
                 uint32_t size) {
    if (!description.Find(id))
      return;
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({bank, offset, size});

    llvm::cantFail(layout.Add(id, std::move(location)));
  };
  const RegisterID gpr_slots[] = {
      gpr_pc_riscv,  gpr_x1_riscv,  gpr_x2_riscv,  gpr_x3_riscv,  gpr_x4_riscv,
      gpr_x5_riscv,  gpr_x6_riscv,  gpr_x7_riscv,  gpr_x8_riscv,  gpr_x9_riscv,
      gpr_x10_riscv, gpr_x11_riscv, gpr_x12_riscv, gpr_x13_riscv, gpr_x14_riscv,
      gpr_x15_riscv, gpr_x16_riscv, gpr_x17_riscv, gpr_x18_riscv, gpr_x19_riscv,
      gpr_x20_riscv, gpr_x21_riscv, gpr_x22_riscv, gpr_x23_riscv, gpr_x24_riscv,
      gpr_x25_riscv, gpr_x26_riscv, gpr_x27_riscv, gpr_x28_riscv, gpr_x29_riscv,
      gpr_x30_riscv, gpr_x31_riscv};
  for (size_t slot = 0; slot != std::size(gpr_slots); ++slot)
    add(gpr_slots[slot], 0, slot * 8, 8);
  RegisterLocation zero;
  zero.kind = RegisterLocation::Constant;
  zero.constant.resize(8);

  llvm::cantFail(layout.Add(gpr_x0_riscv, std::move(zero)));
  if (description.Find(fpr_f0_riscv)) {
    llvm::cantFail(layout.AddBank(1, sizeof(linux_riscv64::FPR)));
    const RegisterID fp_slots[] = {
        fpr_f0_riscv,  fpr_f1_riscv,  fpr_f2_riscv,  fpr_f3_riscv,
        fpr_f4_riscv,  fpr_f5_riscv,  fpr_f6_riscv,  fpr_f7_riscv,
        fpr_f8_riscv,  fpr_f9_riscv,  fpr_f10_riscv, fpr_f11_riscv,
        fpr_f12_riscv, fpr_f13_riscv, fpr_f14_riscv, fpr_f15_riscv,
        fpr_f16_riscv, fpr_f17_riscv, fpr_f18_riscv, fpr_f19_riscv,
        fpr_f20_riscv, fpr_f21_riscv, fpr_f22_riscv, fpr_f23_riscv,
        fpr_f24_riscv, fpr_f25_riscv, fpr_f26_riscv, fpr_f27_riscv,
        fpr_f28_riscv, fpr_f29_riscv, fpr_f30_riscv, fpr_f31_riscv};
    for (size_t slot = 0; slot != std::size(fp_slots); ++slot)
      add(fp_slots[slot], 1, slot * 8, 8);
    add(fpr_fcsr_riscv, 1, 256, 4);
  }
  llvm::cantFail(layout.Validate(description));
  return layout;
}

RegisterModel
lldb_private::CreateLinuxRISCV64RegisterModel(const ArchSpec &arch,
                                              Flags features) {
  auto description = RegisterInfo_riscv64::CreateDescription(features);
  auto layout = CreateLayout(*description, arch.GetByteOrder());
  return {std::move(description), std::move(layout)};
}
