//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/Linux/RegisterModelLinux_loongarch64.h"
#include "lldb/Register/Arch/lldb-loongarch-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-loongarch-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_loongarch64.h"
#include "llvm/ADT/STLExtras.h"
#include <algorithm>
#include <iterator>
using namespace lldb_private;

static std::shared_ptr<const RegisterDescription> LinuxDescription() {
  static const auto description = [] {
    auto arch = RegisterInfo_loongarch64::CreateDescription();
    std::vector<RegisterDescriptor> registers(arch->GetRegisters().begin(),
                                              arch->GetRegisters().end());
    std::vector<RegisterGroup> groups(arch->GetGroups().begin(),
                                      arch->GetGroups().end());
    // Linux syscall state and padding slots are extensions of the CPU catalog.
    struct Extra {
      RegisterID id;
      const char *name;
      uint32_t dwarf;
    };
    const Extra extras[] = {
        {gpr_orig_a0_loongarch, "orig_a0", loongarch_dwarf::dwarf_gpr_orig_a0},
        {gpr_reserved0_loongarch, "reserved0",
         loongarch_dwarf::dwarf_gpr_reserved0},
        {gpr_reserved1_loongarch, "reserved1",
         loongarch_dwarf::dwarf_gpr_reserved1},
        {gpr_reserved2_loongarch, "reserved2",
         loongarch_dwarf::dwarf_gpr_reserved2},
        {gpr_reserved3_loongarch, "reserved3",
         loongarch_dwarf::dwarf_gpr_reserved3},
        {gpr_reserved4_loongarch, "reserved4",
         loongarch_dwarf::dwarf_gpr_reserved4},
        {gpr_reserved5_loongarch, "reserved5",
         loongarch_dwarf::dwarf_gpr_reserved5},
        {gpr_reserved6_loongarch, "reserved6",
         loongarch_dwarf::dwarf_gpr_reserved6},
        {gpr_reserved7_loongarch, "reserved7",
         loongarch_dwarf::dwarf_gpr_reserved7},
        {gpr_reserved8_loongarch, "reserved8",
         loongarch_dwarf::dwarf_gpr_reserved8},
        {gpr_reserved9_loongarch, "reserved9",
         loongarch_dwarf::dwarf_gpr_reserved9}};
    for (const auto &extra : extras) {
      RegisterDescriptor reg;
      reg.id = extra.id;
      reg.name = extra.name;
      reg.byte_size = 8;
      reg.numbers[lldb::eRegisterKindLLDB] = extra.id;
      reg.numbers[lldb::eRegisterKindDWARF] = extra.dwarf;
      reg.numbers[lldb::eRegisterKindEHFrame] = extra.dwarf;
      registers.push_back(std::move(reg));
      groups[0].registers.push_back(extra.id);
    }
    llvm::sort(registers,
               [](const auto &a, const auto &b) { return a.id < b.id; });
    llvm::sort(groups[0].registers);
    return std::make_shared<RegisterDescription>(llvm::cantFail(
        RegisterDescription::Create(std::move(registers), std::move(groups))));
  }();
  return description;
}

static RegisterLayout CreateLayout(const RegisterDescription &description,
                                   lldb::ByteOrder byte_order) {
  RegisterLayout layout(byte_order);
  const uint32_t sizes[] = {360, 272, 512, 1024};
  for (uint32_t bank = 0; bank != 4; ++bank)
    llvm::cantFail(layout.AddBank(bank, sizes[bank]));
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
      gpr_r0_loongarch,        gpr_r1_loongarch,
      gpr_r2_loongarch,        gpr_r3_loongarch,
      gpr_r4_loongarch,        gpr_r5_loongarch,
      gpr_r6_loongarch,        gpr_r7_loongarch,
      gpr_r8_loongarch,        gpr_r9_loongarch,
      gpr_r10_loongarch,       gpr_r11_loongarch,
      gpr_r12_loongarch,       gpr_r13_loongarch,
      gpr_r14_loongarch,       gpr_r15_loongarch,
      gpr_r16_loongarch,       gpr_r17_loongarch,
      gpr_r18_loongarch,       gpr_r19_loongarch,
      gpr_r20_loongarch,       gpr_r21_loongarch,
      gpr_r22_loongarch,       gpr_r23_loongarch,
      gpr_r24_loongarch,       gpr_r25_loongarch,
      gpr_r26_loongarch,       gpr_r27_loongarch,
      gpr_r28_loongarch,       gpr_r29_loongarch,
      gpr_r30_loongarch,       gpr_r31_loongarch,
      gpr_orig_a0_loongarch,   gpr_pc_loongarch,
      gpr_badv_loongarch,      gpr_reserved0_loongarch,
      gpr_reserved1_loongarch, gpr_reserved2_loongarch,
      gpr_reserved3_loongarch, gpr_reserved4_loongarch,
      gpr_reserved5_loongarch, gpr_reserved6_loongarch,
      gpr_reserved7_loongarch, gpr_reserved8_loongarch,
      gpr_reserved9_loongarch};
  for (size_t slot = 0; slot != std::size(gpr_slots); ++slot) {
    if (gpr_slots[slot] == gpr_r0_loongarch)
      continue;
    add(gpr_slots[slot], 0, slot * 8, 8);
  }
  RegisterLocation zero;
  zero.kind = RegisterLocation::Constant;
  zero.constant.resize(8);
  llvm::cantFail(layout.Add(gpr_r0_loongarch, std::move(zero)));
  const RegisterID fp_slots[] = {
      fpr_f0_loongarch,  fpr_f1_loongarch,  fpr_f2_loongarch,
      fpr_f3_loongarch,  fpr_f4_loongarch,  fpr_f5_loongarch,
      fpr_f6_loongarch,  fpr_f7_loongarch,  fpr_f8_loongarch,
      fpr_f9_loongarch,  fpr_f10_loongarch, fpr_f11_loongarch,
      fpr_f12_loongarch, fpr_f13_loongarch, fpr_f14_loongarch,
      fpr_f15_loongarch, fpr_f16_loongarch, fpr_f17_loongarch,
      fpr_f18_loongarch, fpr_f19_loongarch, fpr_f20_loongarch,
      fpr_f21_loongarch, fpr_f22_loongarch, fpr_f23_loongarch,
      fpr_f24_loongarch, fpr_f25_loongarch, fpr_f26_loongarch,
      fpr_f27_loongarch, fpr_f28_loongarch, fpr_f29_loongarch,
      fpr_f30_loongarch, fpr_f31_loongarch};
  for (size_t slot = 0; slot != std::size(fp_slots); ++slot)
    add(fp_slots[slot], 1, slot * 8, 8);
  const RegisterID fcc_slots[] = {fpr_fcc0_loongarch, fpr_fcc1_loongarch,
                                  fpr_fcc2_loongarch, fpr_fcc3_loongarch,
                                  fpr_fcc4_loongarch, fpr_fcc5_loongarch,
                                  fpr_fcc6_loongarch, fpr_fcc7_loongarch};
  for (size_t slot = 0; slot != std::size(fcc_slots); ++slot)
    add(fcc_slots[slot], 1, 256 + slot, 1);
  add(fpr_fcsr_loongarch, 1, 264, 4);
  const RegisterID lsx_slots[] = {
      lsx_vr0_loongarch,  lsx_vr1_loongarch,  lsx_vr2_loongarch,
      lsx_vr3_loongarch,  lsx_vr4_loongarch,  lsx_vr5_loongarch,
      lsx_vr6_loongarch,  lsx_vr7_loongarch,  lsx_vr8_loongarch,
      lsx_vr9_loongarch,  lsx_vr10_loongarch, lsx_vr11_loongarch,
      lsx_vr12_loongarch, lsx_vr13_loongarch, lsx_vr14_loongarch,
      lsx_vr15_loongarch, lsx_vr16_loongarch, lsx_vr17_loongarch,
      lsx_vr18_loongarch, lsx_vr19_loongarch, lsx_vr20_loongarch,
      lsx_vr21_loongarch, lsx_vr22_loongarch, lsx_vr23_loongarch,
      lsx_vr24_loongarch, lsx_vr25_loongarch, lsx_vr26_loongarch,
      lsx_vr27_loongarch, lsx_vr28_loongarch, lsx_vr29_loongarch,
      lsx_vr30_loongarch, lsx_vr31_loongarch};
  for (size_t slot = 0; slot != std::size(lsx_slots); ++slot)
    add(lsx_slots[slot], 2, slot * 16, 16);
  const RegisterID lasx_slots[] = {
      lasx_xr0_loongarch,  lasx_xr1_loongarch,  lasx_xr2_loongarch,
      lasx_xr3_loongarch,  lasx_xr4_loongarch,  lasx_xr5_loongarch,
      lasx_xr6_loongarch,  lasx_xr7_loongarch,  lasx_xr8_loongarch,
      lasx_xr9_loongarch,  lasx_xr10_loongarch, lasx_xr11_loongarch,
      lasx_xr12_loongarch, lasx_xr13_loongarch, lasx_xr14_loongarch,
      lasx_xr15_loongarch, lasx_xr16_loongarch, lasx_xr17_loongarch,
      lasx_xr18_loongarch, lasx_xr19_loongarch, lasx_xr20_loongarch,
      lasx_xr21_loongarch, lasx_xr22_loongarch, lasx_xr23_loongarch,
      lasx_xr24_loongarch, lasx_xr25_loongarch, lasx_xr26_loongarch,
      lasx_xr27_loongarch, lasx_xr28_loongarch, lasx_xr29_loongarch,
      lasx_xr30_loongarch, lasx_xr31_loongarch};
  for (size_t slot = 0; slot != std::size(lasx_slots); ++slot)
    add(lasx_slots[slot], 3, slot * 32, 32);
  llvm::cantFail(layout.Validate(description));
  return layout;
}

RegisterModel
lldb_private::CreateLinuxLoongArch64RegisterModel(const ArchSpec &arch) {
  auto description = LinuxDescription();
  auto layout = CreateLayout(*description, arch.GetByteOrder());
  return {std::move(description), std::move(layout)};
}
