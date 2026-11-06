//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_COMMON_REGISTERINFO_ARM64_H
#define LLDB_REGISTER_COMMON_REGISTERINFO_ARM64_H
#include "lldb/Register/RegisterInfoProvider.h"
#include "lldb/Utility/Flags.h"
namespace lldb_private {
struct Arm64RegisterFeatures {
  bool fp16 = false;
  bool dit = false;
  bool ssbs = false;
  bool gcs = false;
  bool bti = false;
  bool mte = false;
  bool afp = false;
  bool sme = false;
  bool ebf16 = false;
  bool fpmr = false;
  bool poe = false;
  bool pan = false;
  bool uao = false;
  bool nmi = false;
};
} // namespace lldb_private

enum class SVEState : uint8_t {
  // We have yet to look what features there are.
  Unknown,
  // We know that there is no SVE or streaming SVE (SME).
  Disabled,
  // We are in non-streaming mode but SVE is not active.
  FPSIMD,
  // We are in non-streaming mode and SVE is active.
  Full,
  // We are in streaming mode using streaming SVE.
  Streaming,
  // We are in non-streaming mode, and only have SVE while in streaming mode.
  StreamingFPSIMD
};

class RegisterInfo_arm64 : public lldb_private::RegisterInfoProvider {
public:
  enum { GPRegSet = 0, FPRegSet };
  // AArch64 register set mask value
  enum {
    eRegsetMaskDefault = 0,
    eRegsetMaskSVE = 1,
    eRegsetMaskSSVE = 2,
    eRegsetMaskPAuth = 4,
    eRegsetMaskMTE = 8,
    eRegsetMaskTLS = 16,
    eRegsetMaskZA = 32,
    eRegsetMaskZT = 64,
    eRegsetMaskFPMR = 128,
    eRegsetMaskGCS = 256,
    eRegsetMaskPOE = 512,
    eRegsetMaskDynamic = ~1,
  };

  // AArch64 Register set FP/SIMD feature configuration
  enum {
    eVectorQuadwordAArch64,
    eVectorQuadwordAArch64SVE,
    eVectorQuadwordAArch64SVEMax = 256
  };

  RegisterInfo_arm64(
      const lldb_private::ArchSpec &arch, lldb_private::Flags features,
      lldb_private::RegisterLayout layout, uint32_t sve_vq = 0,
      uint32_t za_vq = 0,
      const lldb_private::Arm64RegisterFeatures *type_features = nullptr)
      : RegisterInfoProvider(
            arch, CreateDescription(features, sve_vq, za_vq, type_features),
            std::move(layout)),
        m_opt_regsets(features) {}
  RegisterInfo_arm64(const lldb_private::ArchSpec &arch,
                     lldb_private::Flags features,
                     lldb_private::RegisterModel model)
      : RegisterInfoProvider(arch, std::move(model)), m_opt_regsets(features) {}
  static std::shared_ptr<const lldb_private::RegisterDescription>
  CreateDescription(
      lldb_private::Flags features, uint32_t sve_vq = 0, uint32_t za_vq = 0,
      const lldb_private::Arm64RegisterFeatures *type_features = nullptr);
  static bool VectorSizeIsValid(uint32_t vq) {
    return vq <= eVectorQuadwordAArch64SVEMax;
  }
  bool IsSVEPresent() const { return m_opt_regsets.AnySet(eRegsetMaskSVE); }
  bool IsSSVEPresent() const { return m_opt_regsets.AnySet(eRegsetMaskSSVE); }
  bool IsZAPresent() const { return m_opt_regsets.AnySet(eRegsetMaskZA); }
  bool IsZTPresent() const { return m_opt_regsets.AnySet(eRegsetMaskZT); }
  bool IsPAuthPresent() const { return m_opt_regsets.AnySet(eRegsetMaskPAuth); }
  bool IsMTEPresent() const { return m_opt_regsets.AnySet(eRegsetMaskMTE); }
  bool IsTLSPresent() const { return m_opt_regsets.AnySet(eRegsetMaskTLS); }
  bool IsFPMRPresent() const { return m_opt_regsets.AnySet(eRegsetMaskFPMR); }
  bool IsGCSPresent() const { return m_opt_regsets.AnySet(eRegsetMaskGCS); }
  bool IsPOEPresent() const { return m_opt_regsets.AnySet(eRegsetMaskPOE); }

  bool IsGPR(unsigned reg) const;
  bool IsFPR(unsigned reg) const;
  bool IsSVEReg(unsigned reg) const;
  bool IsSVEZReg(unsigned reg) const;
  bool IsSVEPReg(unsigned reg) const;
  bool IsSVERegVG(unsigned reg) const;
  bool IsSVERegFFR(unsigned reg) const;
  bool IsPAuthReg(unsigned reg) const;
  bool IsMTEReg(unsigned reg) const;
  bool IsTLSReg(unsigned reg) const;
  bool IsSMEReg(unsigned reg) const;
  bool IsSMERegZA(unsigned reg) const;
  bool IsSMERegZT(unsigned reg) const;
  bool IsFPMRReg(unsigned reg) const;
  bool IsGCSReg(unsigned reg) const;
  bool IsPOEReg(unsigned reg) const;

  uint32_t GetRegNumSVEZ0() const;
  uint32_t GetRegNumSVEFFR() const;
  uint32_t GetRegNumFPCR() const;
  uint32_t GetRegNumFPSR() const;
  uint32_t GetRegNumFPV0() const;
  uint32_t GetRegNumSVEVG() const;
  uint32_t GetRegNumSMESVG() const;

protected:
  lldb_private::Flags m_opt_regsets;

private:
  bool InGroup(unsigned number, llvm::StringRef group) const;
  uint32_t Number(llvm::StringRef name) const;
};
#endif
