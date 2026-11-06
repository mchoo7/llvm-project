//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_riscv64.h"
#include "lldb/Register/Arch/lldb-riscv-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/lldb-private-types.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Compiler.h"
#include <cassert>
#include <cstddef>
#include <iterator>

using namespace lldb_private;

// These tables describe values, not positions in an operating-system buffer.
#define GPR_OFFSET(idx) 0
#define FPR_OFFSET(idx) 0
#define DECLARE_REGISTER_INFOS_RISCV64_STRUCT
#include "Register/Arch/RegisterDescriptions_riscv64.inc"
#undef DECLARE_REGISTER_INFOS_RISCV64_STRUCT
#undef GPR_OFFSET
#undef FPR_OFFSET

// Number of register sets provided by this context.
enum {
  k_num_gpr_registers = gpr_last_riscv - gpr_first_riscv + 1,
  k_num_fpr_registers = fpr_last_riscv - fpr_first_riscv + 1,
  k_num_register_sets_default = 1
};

// RISC-V64 general purpose registers.
static const uint32_t g_gpr_regnums_riscv64[] = {
    gpr_pc_riscv,  gpr_ra_riscv,       gpr_sp_riscv,  gpr_x3_riscv,
    gpr_x4_riscv,  gpr_x5_riscv,       gpr_x6_riscv,  gpr_x7_riscv,
    gpr_fp_riscv,  gpr_x9_riscv,       gpr_x10_riscv, gpr_x11_riscv,
    gpr_x12_riscv, gpr_x13_riscv,      gpr_x14_riscv, gpr_x15_riscv,
    gpr_x16_riscv, gpr_x17_riscv,      gpr_x18_riscv, gpr_x19_riscv,
    gpr_x20_riscv, gpr_x21_riscv,      gpr_x22_riscv, gpr_x23_riscv,
    gpr_x24_riscv, gpr_x25_riscv,      gpr_x26_riscv, gpr_x27_riscv,
    gpr_x28_riscv, gpr_x29_riscv,      gpr_x30_riscv, gpr_x31_riscv,
    gpr_x0_riscv,  LLDB_INVALID_REGNUM};

static_assert(((sizeof g_gpr_regnums_riscv64 /
                sizeof g_gpr_regnums_riscv64[0]) -
               1) == k_num_gpr_registers,
              "g_gpr_regnums_riscv64 has wrong number of register infos");

// Register sets for RISC-V64.
static const lldb_private::RegisterSet g_reg_set_gpr_riscv64 = {
    "General Purpose Registers", "gpr", k_num_gpr_registers,
    g_gpr_regnums_riscv64};
static const lldb_private::RegisterSet g_reg_set_fpr_riscv64 = {
    "Floating Point Registers", "fpr", k_num_fpr_registers, nullptr};

std::shared_ptr<const RegisterDescription>
RegisterInfo_riscv64::CreateDescription(Flags features) {
  auto build = [](bool has_fp) {
    std::vector<RegisterInfo> registers(
        std::begin(g_register_infos_riscv64_gpr),
        std::end(g_register_infos_riscv64_gpr));
    std::vector<RegisterSet> groups{g_reg_set_gpr_riscv64};
    std::vector<uint32_t> fp_indices;
    if (has_fp) {
      for (size_t i = 0; i != std::size(g_register_infos_riscv64_fpr); ++i)
        fp_indices.push_back(registers.size() + i);
      registers.insert(registers.end(),
                       std::begin(g_register_infos_riscv64_fpr),
                       std::end(g_register_infos_riscv64_fpr));
      groups.push_back(g_reg_set_fpr_riscv64);
      groups.back().registers = fp_indices.data();
    }
    auto imported =
        llvm::cantFail(RegisterDescription::FromLegacy(registers, groups));
    std::vector<RegisterDescriptor> values(imported.GetRegisters().begin(),
                                           imported.GetRegisters().end());
    for (auto &reg : values)
      if (reg.id == gpr_x0_riscv)
        reg.constant_value.resize(reg.byte_size, 0);
    return std::make_shared<RegisterDescription>(
        llvm::cantFail(RegisterDescription::Create(
            std::move(values),
            std::vector<RegisterGroup>(imported.GetGroups().begin(),
                                       imported.GetGroups().end()))));
  };
  // Emulators can return compatibility records by value; their names retain
  // this shared architecture lifetime after a temporary provider is destroyed.
  static const auto gp = build(false);
  static const auto gp_fp = build(true);
  return features.AnySet(eRegsetMaskFP) ? gp_fp : gp;
}

RegisterInfo_riscv64::RegisterInfo_riscv64(const ArchSpec &arch, Flags features,
                                           RegisterLayout layout)
    : RegisterInfoProvider(arch, CreateDescription(features),
                           std::move(layout)),
      m_features(features) {
  assert(arch.GetMachine() == llvm::Triple::riscv64);
}
