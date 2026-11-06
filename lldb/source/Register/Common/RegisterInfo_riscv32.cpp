//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_riscv32.h"
#include "lldb/Register/Arch/lldb-riscv-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/lldb-private-types.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/FormatVariadic.h"
#include <cassert>
#include <cstddef>
#include <iterator>
using namespace lldb_private;

#define GPR_OFFSET(idx) 0
#define FPR_OFFSET(idx) 0
#define REG_CONTEXT_SIZE 0
#define DECLARE_REGISTER_INFOS_RISCV32_STRUCT
#include "Register/Arch/RegisterDescriptions_riscv32.inc"
#undef DECLARE_REGISTER_INFOS_RISCV32_STRUCT
#undef GPR_OFFSET
#undef FPR_OFFSET
#undef REG_CONTEXT_SIZE

// Number of register sets provided by this context.
enum {
  k_num_gpr_registers = gpr_last_riscv - gpr_first_riscv + 1,
  k_num_fpr_registers = fpr_last_riscv - fpr_first_riscv + 1,
  k_num_register_sets = 2
};

// RISC-V32 general purpose registers.
static const uint32_t g_gpr_regnums_riscv32[] = {
    gpr_pc_riscv,  gpr_ra_riscv,       gpr_sp_riscv,  gpr_x3_riscv,
    gpr_x4_riscv,  gpr_x5_riscv,       gpr_x6_riscv,  gpr_x7_riscv,
    gpr_fp_riscv,  gpr_x9_riscv,       gpr_x10_riscv, gpr_x11_riscv,
    gpr_x12_riscv, gpr_x13_riscv,      gpr_x14_riscv, gpr_x15_riscv,
    gpr_x16_riscv, gpr_x17_riscv,      gpr_x18_riscv, gpr_x19_riscv,
    gpr_x20_riscv, gpr_x21_riscv,      gpr_x22_riscv, gpr_x23_riscv,
    gpr_x24_riscv, gpr_x25_riscv,      gpr_x26_riscv, gpr_x27_riscv,
    gpr_x28_riscv, gpr_x29_riscv,      gpr_x30_riscv, gpr_x31_riscv,
    gpr_x0_riscv,  LLDB_INVALID_REGNUM};

static_assert(((sizeof g_gpr_regnums_riscv32 /
                sizeof g_gpr_regnums_riscv32[0]) -
               1) == k_num_gpr_registers,
              "g_gpr_regnums_riscv32 has wrong number of register infos");

// RISC-V32 floating point registers.
static const uint32_t g_fpr_regnums_riscv32[] = {
    fpr_f0_riscv,   fpr_f1_riscv,       fpr_f2_riscv,  fpr_f3_riscv,
    fpr_f4_riscv,   fpr_f5_riscv,       fpr_f6_riscv,  fpr_f7_riscv,
    fpr_f8_riscv,   fpr_f9_riscv,       fpr_f10_riscv, fpr_f11_riscv,
    fpr_f12_riscv,  fpr_f13_riscv,      fpr_f14_riscv, fpr_f15_riscv,
    fpr_f16_riscv,  fpr_f17_riscv,      fpr_f18_riscv, fpr_f19_riscv,
    fpr_f20_riscv,  fpr_f21_riscv,      fpr_f22_riscv, fpr_f23_riscv,
    fpr_f24_riscv,  fpr_f25_riscv,      fpr_f26_riscv, fpr_f27_riscv,
    fpr_f28_riscv,  fpr_f29_riscv,      fpr_f30_riscv, fpr_f31_riscv,
    fpr_fcsr_riscv, LLDB_INVALID_REGNUM};

static_assert(((sizeof g_fpr_regnums_riscv32 /
                sizeof g_fpr_regnums_riscv32[0]) -
               1) == k_num_fpr_registers,
              "g_fpr_regnums_riscv32 has wrong number of register infos");

// Register sets for RISC-V32.
static const lldb_private::RegisterSet g_reg_sets_riscv32[k_num_register_sets] =
    {{"General Purpose Registers", "gpr", k_num_gpr_registers,
      g_gpr_regnums_riscv32},
     {"Floating Point Registers", "fpr", k_num_fpr_registers,
      g_fpr_regnums_riscv32}};

std::shared_ptr<const RegisterDescription>
RegisterInfo_riscv32::CreateDescription() {
  static const auto description = [] {
    auto imported = llvm::cantFail(RegisterDescription::FromLegacy(
        g_register_infos_riscv32_le, g_reg_sets_riscv32));
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
  }();
  return description;
}

RegisterInfo_riscv32::RegisterInfo_riscv32(const ArchSpec &arch, Flags features,
                                           RegisterLayout layout)
    : RegisterInfo_riscv32(
          arch, features,
          RegisterModel{CreateDescription(), std::move(layout)}) {}

RegisterInfo_riscv32::RegisterInfo_riscv32(const ArchSpec &arch, Flags features,
                                           RegisterModel model)
    : RegisterInfoProvider(arch, std::move(model)), m_features(features) {
  assert(arch.GetMachine() == llvm::Triple::riscv32);
}
void RegisterInfo_riscv32::BuildCSRegInfos(
    llvm::ArrayRef<std::string> features,
    llvm::SmallVectorImpl<lldb_private::RegisterInfo> &cs_reg_infos) {
  cs_reg_infos.clear();

  // Sort and deduplicate to make the list independent of caller ordering.
  llvm::SmallVector<llvm::StringRef> normalized_features(features.begin(),
                                                         features.end());
  llvm::sort(normalized_features);
  normalized_features.erase(llvm::unique(normalized_features),
                            normalized_features.end());

  const uint32_t k_num_csr_registers = csr_last_riscv - csr_first_riscv + 1;
  cs_reg_infos.reserve(k_num_csr_registers);

  // Construct default CS register information. CS register information entries
  // are stored in CSR-address order.
  for (uint32_t reg = 0; reg < k_num_csr_registers; ++reg) {
    lldb_private::RegisterInfo csr{};
    for (auto &kind : csr.kinds)
      kind = LLDB_INVALID_REGNUM;

    lldb_private::ConstString name(llvm::formatv("csr_{0:x}", reg).str());
    csr.name = name.GetCString();
    csr.alt_name = csr.name;
    csr.byte_size = 4;
    csr.byte_offset = 0;
    csr.encoding = lldb::eEncodingUint;
    csr.format = lldb::eFormatHex;
    csr.kinds[lldb::eRegisterKindEHFrame] = riscv_dwarf::dwarf_first_csr + reg;
    csr.kinds[lldb::eRegisterKindDWARF] = riscv_dwarf::dwarf_first_csr + reg;
    csr.kinds[lldb::eRegisterKindGeneric] = LLDB_INVALID_REGNUM;
    csr.kinds[lldb::eRegisterKindProcessPlugin] = LLDB_INVALID_REGNUM;
    csr.kinds[lldb::eRegisterKindLLDB] = csr_first_riscv + reg;
    csr.value_regs = nullptr;
    csr.invalidate_regs = nullptr;
    csr.register_type = nullptr;

    cs_reg_infos.push_back(csr);
  }

  // Patch application is order-dependent; later patches override earlier ones
  // for the same CSR address.
  ConfigureCSRegInfos("default", cs_reg_infos);

  for (const auto &feature : normalized_features)
    ConfigureCSRegInfos(feature, cs_reg_infos);
}

void RegisterInfo_riscv32::ConfigureCSRegInfos(
    llvm::StringRef feature,
    llvm::SmallVectorImpl<lldb_private::RegisterInfo> &cs_reg_infos) {
  // Initialized on first use so that the patch set does not depend on the
  // initialization order of globals in other translation units.
  static const llvm::StringMap<llvm::ArrayRef<lldb_private::RegisterInfo>>
      g_register_infos_riscv32_csr_patches = {
          {"default", llvm::ArrayRef(g_register_infos_riscv32_csr_patch)},
          {"xqciint",
           llvm::ArrayRef(g_register_infos_riscv32_csr_xqciint_patch)}};

  auto it = g_register_infos_riscv32_csr_patches.find(feature);
  if (it == g_register_infos_riscv32_csr_patches.end())
    return;

  for (const auto &csr : it->second) {
    const uint32_t lldb_reg = csr.kinds[lldb::eRegisterKindLLDB];
    if (lldb_reg < csr_first_riscv || lldb_reg > csr_last_riscv)
      continue;
    uint32_t idx = lldb_reg - csr_first_riscv;
    if (idx < cs_reg_infos.size())
      cs_reg_infos[idx] = csr;
  }
}
