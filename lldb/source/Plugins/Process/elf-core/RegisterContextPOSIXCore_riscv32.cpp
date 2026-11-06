//===-- RegisterContextPOSIXCore_riscv32.cpp ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_riscv32.h"

#include "lldb/Register/Arch/lldb-riscv-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/lldb-defines.h"
#include "lldb/lldb-enumerations.h"
#include "lldb/lldb-private-types.h"
#include "lldb/lldb-private.h"
#include "llvm/Support/Compiler.h"
#include <cstddef>
#include <cstdint>
#include <stddef.h>

#include "lldb/Core/Debugger.h"
#include "lldb/Core/Module.h"
#include "lldb/Register/RegisterCodec.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/TargetParser/SubtargetFeature.h"

using namespace lldb_private;

static std::vector<uint32_t> CopyRegisterListToVector(const uint32_t *regs) {
  if (!regs)
    return {};

  const uint32_t *end = regs;
  while (*end != LLDB_INVALID_REGNUM)
    ++end;

  return std::vector<uint32_t>(regs, end);
}

std::unique_ptr<RegisterContextCorePOSIX_riscv32>
RegisterContextCorePOSIX_riscv32::Create(Thread &thread, const ArchSpec &arch,
                                         const DataExtractor &gpregset,
                                         llvm::ArrayRef<CoreNote> notes) {
  return std::unique_ptr<RegisterContextCorePOSIX_riscv32>(
      new RegisterContextCorePOSIX_riscv32(thread, arch, gpregset, notes));
}

RegisterContextCorePOSIX_riscv32::RegisterContextCorePOSIX_riscv32(
    Thread &thread, const ArchSpec &arch, const DataExtractor &gpregset,
    llvm::ArrayRef<CoreNote> notes)
    : RegisterContext(thread, 0) {
  RegisterInfo_riscv32 cpu(arch, 0, RegisterLayout(arch.GetByteOrder()));
  std::vector<RegisterInfo> g_register_infos_riscv32_gpr,
      g_register_infos_riscv32_fpr;
  for (size_t set_index = 0; set_index < cpu.GetRegisterSetCount();
       ++set_index) {
    const auto *set = cpu.GetRegisterSet(set_index);
    auto &values = set_index == 0 ? g_register_infos_riscv32_gpr
                                  : g_register_infos_riscv32_fpr;
    for (uint32_t index : llvm::ArrayRef(set->registers, set->num_registers))
      values.push_back(cpu.GetRegisterInfo()[index]);
  }
  const auto k_num_gpr_registers = g_register_infos_riscv32_gpr.size();
  const auto k_num_fpr_registers = g_register_infos_riscv32_fpr.size();
  llvm::SmallVector<std::string> features;
  GetFeatures(features);
  llvm::SmallVector<lldb_private::RegisterInfo> reg_infos_riscv32_csr;
  RegisterInfo_riscv32::BuildCSRegInfos(features, reg_infos_riscv32_csr);
  uint32_t k_num_csr_registers = reg_infos_riscv32_csr.size();
  const ArchSpec &target_arch = arch;
  const llvm::Triple triple = target_arch.GetTriple();
  const lldb::ByteOrder byte_order = target_arch.GetByteOrder();

  std::vector<RegisterDescriptionBuilder::Register> registers;
  uint32_t byte_offset = 0;
  std::map<RegisterID, uint64_t> csr_offsets;

  // Build dynamic register information for GPR.
  const lldb_private::ConstString gpr_set("GPR");
  m_gpregset.SetData(std::make_shared<DataBufferHeap>(gpregset.GetDataStart(),
                                                      gpregset.GetByteSize()));
  if (m_gpregset.GetByteSize() >= g_register_infos_riscv32_gpr[0].byte_size) {
    // A note may omit a synthetic zero slot or end before all registers.
    m_gpregset.SetByteOrder(gpregset.GetByteOrder());
    for (const auto &gpr : g_register_infos_riscv32_gpr) {
      registers.push_back(BuildDynamicRegister(gpr, gpr_set, byte_offset));
      byte_offset += gpr.byte_size;
    }
  }

  // Build dynamic register information for FPR.
  const lldb_private::ConstString fpr_set("FPR");
  m_fpregset = getRegset(notes, triple, FPR_Desc);
  if (m_fpregset.GetByteSize() >= g_register_infos_riscv32_fpr[0].byte_size) {
    // A note may omit a synthetic zero slot or end before all registers.
    m_fpregset.SetByteOrder(byte_order);
    for (const auto &fpr : g_register_infos_riscv32_fpr) {
      registers.push_back(BuildDynamicRegister(fpr, fpr_set, byte_offset));
      byte_offset += fpr.byte_size;
    }
  }

  // Build dynamic register information for CSR.
  const lldb_private::ConstString csr_set("CSR");
  m_csregset = getRegset(notes, triple, RISCV32_CSREGMAP_Desc);
  if (m_csregset.GetByteSize() >=
      (sizeof(csr_kv_t::addr) + sizeof(csr_kv_t::val))) {
    // CSR is available.
    m_csregset.SetByteOrder(byte_order);
    lldb::offset_t offset = 0;
    std::vector<uint32_t> csregset_regnums = {};
    while (m_csregset.BytesLeft(offset) >= sizeof(csr_kv_t)) {
      uint32_t csr_addr = m_csregset.GetU32(&offset);
      if (csr_addr >= k_num_csr_registers) {
        (void)m_csregset.GetU32(&offset);
        continue;
      }
      if (csregset_regnums.size() == k_num_csr_registers) {
        Debugger::ReportWarning(
            llvm::formatv("parsed the permissible number of CSRs {0:x} but "
                          "NT_CSREGMAP has more; skipping the remaining CSRs",
                          k_num_csr_registers));
        break;
      }
      if (llvm::is_contained(csregset_regnums, csr_addr)) {
        Debugger::ReportWarning(
            llvm::formatv("encountered a duplicate CSR while parsing "
                          "NT_CSREGMAP: {0}; skipping",
                          reg_infos_riscv32_csr[csr_addr].name));
      } else {
        csregset_regnums.push_back(csr_addr);
        const RegisterInfo &csr = reg_infos_riscv32_csr[csr_addr];
        csr_offsets[csr.kinds[lldb::eRegisterKindLLDB]] = offset;
        auto dynamic = BuildDynamicRegister(csr, csr_set, byte_offset);
        // FCSR can be present both in the FP note and in the CSR map. Keep
        // both source locations addressable without duplicating display names.
        if (llvm::any_of(registers, [&](const auto &reg) {
              return reg.name == dynamic.name;
            })) {
          dynamic.name =
              dynamic.alt_name && dynamic.alt_name != dynamic.name
                  ? dynamic.alt_name
                  : ConstString(llvm::formatv("csr_{0:x}", csr_addr).str());
          dynamic.alt_name = ConstString(csr.name);
        }
        registers.push_back(std::move(dynamic));
        byte_offset += csr.byte_size;
      }
      // Consume and skip the CSR value to advance to the next entry.
      (void)m_csregset.GetU32(&offset);
    }
  }

  RegisterDescriptionBuilder builder;
  builder.SetRegisterInfo(std::move(registers), arch);
  auto model = llvm::cantFail(builder.BuildModel(arch.GetByteOrder()));
  RegisterLayout layout(arch.GetByteOrder());
  llvm::cantFail(layout.AddBank(0, k_num_gpr_registers * 4));
  llvm::cantFail(layout.AddBank(1, k_num_fpr_registers * 4));
  llvm::cantFail(layout.AddBank(2, m_csregset.GetByteSize()));
  for (const auto &reg : model.description->GetRegisters()) {
    RegisterLocation location;

    if (reg.id == gpr_x0_riscv) {
      location.kind = RegisterLocation::Constant;
      location.constant.resize(reg.byte_size, 0);
    } else {
      location.kind = RegisterLocation::Stored;
      if (reg.id < fpr_first_riscv)
        location.pieces.push_back(
            {0, (reg.id - gpr_first_riscv) * 4, reg.byte_size});
      else if (reg.id <= fpr_last_riscv)
        location.pieces.push_back(
            {1, (reg.id - fpr_first_riscv) * 4, reg.byte_size});
      else
        location.pieces.push_back({2, csr_offsets.at(reg.id), reg.byte_size});
    }
    llvm::cantFail(layout.Add(reg.id, std::move(location)));
  }
  m_reg_infos_up = std::make_unique<RegisterInfoProvider>(
      arch, std::move(model.description), std::move(layout));
}

RegisterContextCorePOSIX_riscv32::~RegisterContextCorePOSIX_riscv32() = default;

void RegisterContextCorePOSIX_riscv32::InvalidateAllRegisters() {}

size_t RegisterContextCorePOSIX_riscv32::GetRegisterCount() {
  return m_reg_infos_up->GetRegisterCount();
}

const lldb_private::RegisterInfo *
RegisterContextCorePOSIX_riscv32::GetRegisterInfoAtIndex(size_t reg) {
  if (reg < GetRegisterCount())
    return &m_reg_infos_up->GetRegisterInfo()[static_cast<uint32_t>(reg)];
  return nullptr;
}

size_t RegisterContextCorePOSIX_riscv32::GetRegisterSetCount() {
  return m_reg_infos_up->GetRegisterSetCount();
}

const lldb_private::RegisterSet *
RegisterContextCorePOSIX_riscv32::GetRegisterSet(size_t set) {
  return m_reg_infos_up->GetRegisterSet(static_cast<uint32_t>(set));
}

bool RegisterContextCorePOSIX_riscv32::ReadRegister(
    const RegisterInfo *reg_info, RegisterValue &value) {
  if (!reg_info)
    return false;
  auto *reg = m_reg_infos_up->GetDescription().Find(reg_info->name);
  if (!reg)
    return false;
  auto result = RegisterCodec::Read(
      m_reg_infos_up->GetDescription(), m_reg_infos_up->GetLayout(), reg->id,
      {{0, {m_gpregset.GetDataStart(), m_gpregset.GetByteSize()}},
       {1, {m_fpregset.GetDataStart(), m_fpregset.GetByteSize()}},
       {2, {m_csregset.GetDataStart(), m_csregset.GetByteSize()}}});
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_riscv32::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &value) {
  return false;
}

lldb_private::RegisterDescriptionBuilder::Register
RegisterContextCorePOSIX_riscv32::BuildDynamicRegister(
    const lldb_private::RegisterInfo &reg_info,
    const lldb_private::ConstString &set_name, uint32_t byte_offset) {
  return RegisterDescriptionBuilder::Register{
      lldb_private::ConstString(reg_info.name),
      lldb_private::ConstString(reg_info.alt_name),
      set_name,
      reg_info.byte_size,
      byte_offset,
      reg_info.encoding,
      reg_info.format,
      reg_info.kinds[lldb::eRegisterKindDWARF],
      reg_info.kinds[lldb::eRegisterKindEHFrame],
      reg_info.kinds[lldb::eRegisterKindGeneric],
      reg_info.kinds[lldb::eRegisterKindProcessPlugin],
      CopyRegisterListToVector(reg_info.value_regs),
      CopyRegisterListToVector(reg_info.invalidate_regs),
      /*value_reg_offset=*/0,
      reg_info.register_type,
      reg_info.kinds[lldb::eRegisterKindLLDB]};
}

void RegisterContextCorePOSIX_riscv32::GetFeatures(
    llvm::SmallVectorImpl<std::string> &features) const {
  Log *log = GetLog(LLDBLog::Process);
  features.clear();

  if (!m_thread.IsValid())
    return;

  auto process_sp = m_thread.GetProcess();
  if (!process_sp)
    return;

  auto target = process_sp->CalculateTarget();
  if (!target)
    return;

  auto module_sp = target->GetExecutableModule();
  if (!module_sp)
    return;

  // ObjectFileELF::ParseRISCVAttributes should've already parsed features and
  // stored them in the module's ArchSpec via ArchSpec::SetSubtargetFeatures.
  std::vector<std::string> raw_features =
      module_sp->GetArchitecture().GetSubtargetFeatures().getFeatures();

  if (raw_features.empty()) {
    LLDB_LOG(log, "no RISC-V subtarget feature found in module ArchSpec");
    return;
  }

  features.reserve(raw_features.size());
  for (const auto &feature : raw_features) {
    if (feature.empty() || !llvm::SubtargetFeatures::isEnabled(feature))
      continue;
    auto stripped = llvm::SubtargetFeatures::StripFlag(feature);
    if (!stripped.empty())
      features.emplace_back(stripped);
  }
}
