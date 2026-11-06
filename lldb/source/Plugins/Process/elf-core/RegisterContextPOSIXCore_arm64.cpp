//===-- RegisterContextPOSIXCore_arm64.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextPOSIXCore_arm64.h"
#include "lldb/Register/Common/RegisterInfo_arm64.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterModelFreeBSD_arm64.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_arm64.h"
#include "llvm/Support/Endian.h"

#include "Plugins/Process/Utility/AuxVector.h"
#include "Plugins/Process/elf-core/ProcessElfCore.h"
#include "Plugins/Process/elf-core/RegisterUtilities.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/RegisterValue.h"

#include <algorithm>
#include <memory>

using namespace lldb_private;

std::unique_ptr<RegisterContextCorePOSIX_arm64>
RegisterContextCorePOSIX_arm64::Create(Thread &thread, const ArchSpec &arch,
                                       const DataExtractor &gpregset,
                                       llvm::ArrayRef<CoreNote> notes) {
  Flags opt_regsets = RegisterInfo_arm64::eRegsetMaskDefault;

  DataExtractor ssve_data =
      getRegset(notes, arch.GetTriple(), AARCH64_SSVE_Desc);
  if (ssve_data.GetByteSize() >= sizeof(sve::user_sve_header))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskSSVE);

  DataExtractor sve_data = getRegset(notes, arch.GetTriple(), AARCH64_SVE_Desc);
  if (sve_data.GetByteSize() >= sizeof(sve::user_sve_header))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskSVE);

  // Pointer Authentication register set data is based on struct
  // user_pac_mask declared in ptrace.h. See reference implementation
  // in Linux kernel source at arch/arm64/include/uapi/asm/ptrace.h.
  DataExtractor pac_data = getRegset(notes, arch.GetTriple(), AARCH64_PAC_Desc);
  if (pac_data.GetByteSize() >= sizeof(uint64_t) * 2)
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskPAuth);

  DataExtractor tls_data = getRegset(notes, arch.GetTriple(), AARCH64_TLS_Desc);
  // A valid note will always contain at least one register, "tpidr". It may
  // expand in future.
  if (tls_data.GetByteSize() >= sizeof(uint64_t))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskTLS);

  DataExtractor za_data = getRegset(notes, arch.GetTriple(), AARCH64_ZA_Desc);
  // Nothing if ZA is not present, just the header if it is disabled.
  if (za_data.GetByteSize() >= sizeof(sve::user_za_header))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskZA);

  DataExtractor mte_data = getRegset(notes, arch.GetTriple(), AARCH64_MTE_Desc);
  if (mte_data.GetByteSize() >= sizeof(uint64_t))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskMTE);

  DataExtractor zt_data = getRegset(notes, arch.GetTriple(), AARCH64_ZT_Desc);
  // Although ZT0 can be in a disabled state like ZA can, the kernel reports
  // its content as 0s in that state. Therefore even a disabled ZT0 will have
  // a note containing those 0s. ZT0 is a 512 bit / 64 byte register.
  if (zt_data.GetByteSize() >= 64)
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskZT);

  DataExtractor fpmr_data =
      getRegset(notes, arch.GetTriple(), AARCH64_FPMR_Desc);
  if (fpmr_data.GetByteSize() >= sizeof(uint64_t))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskFPMR);

  DataExtractor gcs_data = getRegset(notes, arch.GetTriple(), AARCH64_GCS_Desc);
  struct __attribute__((packed)) gcs_regs {
    uint64_t features_enabled;
    uint64_t features_locked;
    uint64_t gcspr_e0;
  };
  if (gcs_data.GetByteSize() >= sizeof(gcs_regs))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskGCS);

  DataExtractor poe_data = getRegset(notes, arch.GetTriple(), AARCH64_POE_Desc);
  struct poe_regs {
    uint64_t por_el0_reg;
  };
  if (poe_data.GetByteSize() >= sizeof(poe_regs))
    opt_regsets.Set(RegisterInfo_arm64::eRegsetMaskPOE);

  auto &process = static_cast<ProcessElfCore &>(*thread.GetProcess());
  AuxVector auxv(process.GetAuxvData());
  const bool is_freebsd = arch.GetTriple().isOSFreeBSD();
  const uint64_t hwcap =
      auxv.GetAuxValue(is_freebsd ? AuxVector::AUXV_FREEBSD_AT_HWCAP
                                  : AuxVector::AUXV_AT_HWCAP)
          .value_or(0);
  const uint64_t hwcap2 =
      auxv.GetAuxValue(AuxVector::AUXV_AT_HWCAP2).value_or(0);
  const uint64_t hwcap3 =
      is_freebsd ? 0 : auxv.GetAuxValue(AuxVector::AUXV_AT_HWCAP3).value_or(0);
  std::unique_ptr<RegisterInfo_arm64> register_info_up;
  std::optional<linux_arm64::RegisterConfig> config;
  if (arch.GetTriple().isOSFreeBSD())
    register_info_up = std::make_unique<RegisterInfo_arm64>(
        arch, 0, CreateFreeBSDArm64RegisterModel(arch, hwcap, hwcap2));
  else {
    config.emplace();
    config->features = opt_regsets;
    config->hwcap = hwcap;
    config->hwcap2 = hwcap2;
    config->hwcap3 = hwcap3;
    register_info_up = std::make_unique<RegisterInfo_arm64>(
        arch, opt_regsets, CreateLinuxArm64RegisterModel(arch, *config));
  }
  return std::unique_ptr<RegisterContextCorePOSIX_arm64>(
      new RegisterContextCorePOSIX_arm64(thread, std::move(register_info_up),
                                         gpregset, notes, std::move(config)));
}

RegisterContextCorePOSIX_arm64::RegisterContextCorePOSIX_arm64(
    Thread &thread, std::unique_ptr<RegisterInfo_arm64> register_info,
    const DataExtractor &gpregset, llvm::ArrayRef<CoreNote> notes,
    std::optional<linux_arm64::RegisterConfig> config)
    : RegisterContextCore_arm64(thread, std::move(register_info)),
      m_register_config(std::move(config)) {
  ::memset(&m_sme_pseudo_regs, 0, sizeof(m_sme_pseudo_regs));

  m_gpr_data.SetData(std::make_shared<DataBufferHeap>(gpregset.GetDataStart(),
                                                      gpregset.GetByteSize()));
  m_gpr_data.SetByteOrder(gpregset.GetByteOrder());

  const llvm::Triple &target_triple =
      m_register_info_up->GetTargetArchitecture().GetTriple();
  m_fpr_data = getRegset(notes, target_triple, FPR_Desc);

  if (m_register_info_up->IsSSVEPresent()) {
    m_sve_data = getRegset(notes, target_triple, AARCH64_SSVE_Desc);
    lldb::offset_t flags_offset = 12;
    uint16_t flags = m_sve_data.GetU32(&flags_offset);
    if ((flags & sve::ptrace_regs_mask) == sve::ptrace_regs_sve)
      m_sve_state = SVEState::Streaming;
  }

  if (m_sve_state != SVEState::Streaming && m_register_info_up->IsSVEPresent())
    m_sve_data = getRegset(notes, target_triple, AARCH64_SVE_Desc);

  if (m_register_info_up->IsPAuthPresent())
    m_pac_data = getRegset(notes, target_triple, AARCH64_PAC_Desc);

  if (m_register_info_up->IsTLSPresent())
    m_tls_data = getRegset(notes, target_triple, AARCH64_TLS_Desc);

  if (m_register_info_up->IsZAPresent())
    m_za_data = getRegset(notes, target_triple, AARCH64_ZA_Desc);

  if (m_register_info_up->IsMTEPresent())
    m_mte_data = getRegset(notes, target_triple, AARCH64_MTE_Desc);

  if (m_register_info_up->IsZTPresent())
    m_zt_data = getRegset(notes, target_triple, AARCH64_ZT_Desc);

  if (m_register_info_up->IsFPMRPresent())
    m_fpmr_data = getRegset(notes, target_triple, AARCH64_FPMR_Desc);

  if (m_register_info_up->IsGCSPresent())
    m_gcs_data = getRegset(notes, target_triple, AARCH64_GCS_Desc);

  if (m_register_info_up->IsPOEPresent())
    m_poe_data = getRegset(notes, target_triple, AARCH64_POE_Desc);

  ConfigureRegisterContext();
}

RegisterContextCorePOSIX_arm64::~RegisterContextCorePOSIX_arm64() = default;

bool RegisterContextCorePOSIX_arm64::ReadGPR() { return true; }

bool RegisterContextCorePOSIX_arm64::ReadFPR() { return false; }

bool RegisterContextCorePOSIX_arm64::WriteGPR() {
  assert(0);
  return false;
}

bool RegisterContextCorePOSIX_arm64::WriteFPR() {
  assert(0);
  return false;
}

void RegisterContextCorePOSIX_arm64::ConfigureRegisterContext() {
  if (m_sve_data.GetByteSize() > sizeof(sve::user_sve_header)) {
    uint64_t sve_header_field_offset = 8;
    m_sve_vector_length = m_sve_data.GetU16(&sve_header_field_offset);

    if (m_sve_state != SVEState::Streaming) {
      sve_header_field_offset = 12;
      uint16_t sve_header_flags_field =
          m_sve_data.GetU16(&sve_header_field_offset);
      if ((sve_header_flags_field & sve::ptrace_regs_mask) ==
          sve::ptrace_regs_fpsimd)
        m_sve_state = SVEState::FPSIMD;
      else if ((sve_header_flags_field & sve::ptrace_regs_mask) ==
               sve::ptrace_regs_sve)
        m_sve_state = SVEState::Full;
    }

    if (!sve::vl_valid(m_sve_vector_length)) {
      m_sve_state = SVEState::Disabled;
      m_sve_vector_length = 0;
    }
  } else
    m_sve_state = SVEState::Disabled;

  if (m_register_config && m_sve_state != SVEState::Disabled) {
    const uint32_t vq = sve::vq_from_vl(m_sve_vector_length);
    if (RegisterInfo_arm64::VectorSizeIsValid(vq))
      m_register_config->sve_vq = std::max(1u, vq);
  }

  if (m_sve_state == SVEState::Streaming)
    m_sme_pseudo_regs.ctrl_reg |= 1;

  if (m_za_data.GetByteSize() >= sizeof(sve::user_za_header)) {
    lldb::offset_t vlen_offset = 8;
    uint16_t svl = m_za_data.GetU16(&vlen_offset);
    m_sme_pseudo_regs.svg_reg = svl / 8;
    if (m_register_config && m_register_info_up->IsSSVEPresent() &&
        RegisterInfo_arm64::VectorSizeIsValid(svl / 16))
      m_register_config->za_vq = svl / 16;

    // If there is register data then ZA is active. The size of the note may be
    // misleading here so we use the size field of the embedded header.
    lldb::offset_t size_offset = 0;
    uint32_t size = m_za_data.GetU32(&size_offset);
    if (size > sizeof(sve::user_za_header))
      m_sme_pseudo_regs.ctrl_reg |= 1 << 1;
  }
  if (m_register_config) {
    m_register_config->sve_state = m_sve_state;
    m_register_info_up->SetRegisterModel(CreateLinuxArm64RegisterModel(
        m_register_info_up->GetTargetArchitecture(), *m_register_config,
        &m_register_info_up->GetDescription()));
  }
}

bool RegisterContextCorePOSIX_arm64::ReadRegister(const RegisterInfo *reg_info,
                                                  RegisterValue &value) {
  if (!reg_info)
    return false;
  std::vector<uint8_t> inactive_za;
  llvm::ArrayRef<uint8_t> za(m_za_data.GetDataStart(), m_za_data.GetByteSize());
  const auto *descriptor =
      m_register_info_up->GetDescription().Find(reg_info->name);
  if (descriptor && descriptor->name == "za") {
    if (m_za_data.GetByteSize() < sizeof(sve::user_za_header))
      return false;
    lldb::offset_t offset = 0;
    if (m_za_data.GetU32(&offset) == sizeof(sve::user_za_header)) {
      inactive_za.resize(sizeof(sve::user_za_header) + descriptor->byte_size,
                         0);
      za = inactive_za;
    }
  }
  uint8_t pseudo[16];
  auto order = m_register_info_up->GetTargetArchitecture().GetByteOrder() ==
                       lldb::eByteOrderBig
                   ? llvm::endianness::big
                   : llvm::endianness::little;
  llvm::support::endian::write64(pseudo, m_sme_pseudo_regs.ctrl_reg, order);
  llvm::support::endian::write64(pseudo + 8, m_sme_pseudo_regs.svg_reg, order);
  auto result = m_register_info_up->ReadRegister(
      *reg_info,
      {{linux_arm64::GP, {m_gpr_data.GetDataStart(), m_gpr_data.GetByteSize()}},
       {linux_arm64::FP, {m_fpr_data.GetDataStart(), m_fpr_data.GetByteSize()}},
       {linux_arm64::SVE,
        {m_sve_data.GetDataStart(), m_sve_data.GetByteSize()}},
       {linux_arm64::PAC,
        {m_pac_data.GetDataStart(), m_pac_data.GetByteSize()}},
       {linux_arm64::MTE,
        {m_mte_data.GetDataStart(), m_mte_data.GetByteSize()}},
       {linux_arm64::TLS,
        {m_tls_data.GetDataStart(), m_tls_data.GetByteSize()}},
       {linux_arm64::ZT, {m_zt_data.GetDataStart(), m_zt_data.GetByteSize()}},
       {linux_arm64::FPMR,
        {m_fpmr_data.GetDataStart(), m_fpmr_data.GetByteSize()}},
       {linux_arm64::GCS,
        {m_gcs_data.GetDataStart(), m_gcs_data.GetByteSize()}},
       {linux_arm64::POE,
        {m_poe_data.GetDataStart(), m_poe_data.GetByteSize()}},
       {linux_arm64::SMEControl, pseudo},
       {linux_arm64::ZA, za}});
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}

bool RegisterContextCorePOSIX_arm64::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  return false;
}

bool RegisterContextCorePOSIX_arm64::WriteRegister(const RegisterInfo *reg_info,
                                                   const RegisterValue &value) {
  return false;
}

bool RegisterContextCorePOSIX_arm64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  return false;
}

bool RegisterContextCorePOSIX_arm64::HardwareSingleStep(bool enable) {
  return false;
}
