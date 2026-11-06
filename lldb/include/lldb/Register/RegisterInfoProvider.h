//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_REGISTERINFOPROVIDER_H
#define LLDB_REGISTER_REGISTERINFOPROVIDER_H

#include "lldb/Register/RegisterCodec.h"
#include "lldb/Utility/ArchSpec.h"

namespace lldb_private {

/// Compatibility with existing contexts is implemented once, independently of
/// architecture construction and of the source register-buffer format.
class RegisterInfoProvider {
public:
  RegisterInfoProvider(const ArchSpec &arch,
                       std::shared_ptr<const RegisterDescription> description,
                       RegisterLayout layout);

  RegisterInfoProvider(const ArchSpec &arch, RegisterModel model)
      : RegisterInfoProvider(arch, std::move(model.description),
                             std::move(model.layout)) {
    m_user_register_count = model.user_register_count;
  }
  virtual ~RegisterInfoProvider() = default;
  RegisterInfoProvider(RegisterInfoProvider &&) = default;
  RegisterInfoProvider &operator=(RegisterInfoProvider &&) = default;
  RegisterInfoProvider(const RegisterInfoProvider &) = delete;
  RegisterInfoProvider &operator=(const RegisterInfoProvider &) = delete;

  /// Replace the description and layout together, preserving compatibility
  /// record addresses when the exposed register count is unchanged.
  void SetRegisterModel(RegisterModel model) {
    m_user_register_count = model.user_register_count;
    Reconfigure(std::move(model.description), std::move(model.layout));
  }

  const ArchSpec &GetTargetArchitecture() const { return m_arch; }
  virtual uint32_t GetUserRegisterCount() const {
    return m_user_register_count == LLDB_INVALID_REGNUM ? GetRegisterCount()
                                                        : m_user_register_count;
  }

  virtual size_t GetGPRSize() const { return GetBankSize(0); }
  virtual size_t GetFPRSize() const { return GetBankSize(1); }
  virtual const RegisterInfo *GetRegisterInfo() const;
  virtual uint32_t GetRegisterCount() const;
  const RegisterSet *GetRegisterSet(size_t index) const;
  size_t GetRegisterSetCount() const;
  size_t GetRegisterSetFromRegisterIndex(uint32_t index) const;
  size_t GetRegisterSetFromRegisterNumber(uint32_t number) const;
  const RegisterInfo *GetRegisterInfoByNumber(uint32_t number) const;

  const RegisterDescription &GetDescription() const {
    return m_view.GetDescription();
  }
  const RegisterLayout &GetLayout() const { return m_layout; }
  size_t GetBankSize(RegisterBankID bank) const;
  llvm::Expected<std::vector<RegisterBankID>>
  GetRegisterBanks(const RegisterInfo &reg, bool writing = false) const;
  llvm::Expected<RegisterValue>
  ReadRegister(const RegisterInfo &reg,
               llvm::ArrayRef<RegisterData> banks) const;
  llvm::Error WriteRegister(const RegisterInfo &reg, const RegisterValue &value,
                            llvm::ArrayRef<MutableRegisterData> banks) const;
  uint32_t GetRegisterValueOffset(const RegisterInfo &reg) const;

protected:
  void Reconfigure(std::shared_ptr<const RegisterDescription> description,
                   RegisterLayout layout);

private:
  uint32_t m_user_register_count = LLDB_INVALID_REGNUM;
  ArchSpec m_arch;
  RegisterLayout m_layout;
  RegisterInfoView m_view;
};

} // namespace lldb_private

#endif
