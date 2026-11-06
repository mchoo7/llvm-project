//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/FreeBSD/RegisterModelFreeBSD_arm64.h"
#include "lldb/Register/Arch/lldb-arm64-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_arm64.h"
using namespace lldb_private;
static RegisterLayout CreateLayout(const ArchSpec &arch) {
  auto description = RegisterInfo_arm64::CreateDescription(0);
  RegisterLayout layout(arch.GetByteOrder());
  llvm::cantFail(layout.AddBank(0, 272));
  llvm::cantFail(layout.AddBank(1, 520));
  for (const auto &reg : description->GetRegisters()) {
    RegisterBankID bank = reg.id <= gpr_w28_arm64 ? 0 : 1;
    uint32_t offset;
    if (reg.id <= gpr_cpsr_arm64)
      offset = reg.id * 8;
    else if (reg.id <= gpr_w28_arm64)
      offset = (reg.id - gpr_w0_arm64) * 8 +
               (arch.GetByteOrder() == lldb::eByteOrderBig ? 4 : 0);
    else if (reg.id == fpu_fpsr_arm64)
      offset = 512;
    else if (reg.id == fpu_fpcr_arm64)
      offset = 516;
    else {
      uint32_t i = reg.id >= fpu_d0_arm64   ? reg.id - fpu_d0_arm64
                   : reg.id >= fpu_s0_arm64 ? reg.id - fpu_s0_arm64
                                            : reg.id - fpu_v0_arm64;
      offset =
          i * 16 +
          (arch.GetByteOrder() == lldb::eByteOrderBig ? 16 - reg.byte_size : 0);
    }
    RegisterLocation loc;
    loc.kind = RegisterLocation::Stored;
    loc.pieces.push_back({bank, offset, reg.byte_size});
    llvm::cantFail(layout.Add(reg.id, std::move(loc)));
  }
  llvm::cantFail(layout.Validate(*description));
  return layout;
}

// FreeBSD's arm64 HWCAP ABI explicitly assigns the same bit positions as Linux:
// freebsd-src/sys/arm64/include/elf.h. Keep decoding at the OS layout boundary.
Arm64RegisterFeatures
lldb_private::DecodeFreeBSDArm64RegisterFeatures(uint64_t hwcap,
                                                 uint64_t hwcap2) {
  Arm64RegisterFeatures features;
  features.fp16 = (hwcap & (1ULL << 9)) && (hwcap & (1ULL << 10));
  features.dit = hwcap & (1ULL << 24);
  features.ssbs = hwcap & (1ULL << 28);
  features.gcs = hwcap & (1ULL << 32);
  features.bti = hwcap2 & (1ULL << 17);
  features.mte = hwcap2 & (1ULL << 18);
  features.afp = hwcap2 & (1ULL << 20);
  features.sme = hwcap2 & (1ULL << 23);
  features.ebf16 = hwcap2 & (1ULL << 32);
  features.fpmr = hwcap2 & (1ULL << 48);
  features.poe = hwcap2 & (1ULL << 63);
  return features;
}

RegisterModel
lldb_private::CreateFreeBSDArm64RegisterModel(const ArchSpec &arch,
                                              uint64_t hwcap, uint64_t hwcap2) {
  auto features = DecodeFreeBSDArm64RegisterFeatures(hwcap, hwcap2);
  return {RegisterInfo_arm64::CreateDescription(0, 0, 0, &features),
          CreateLayout(arch)};
}
