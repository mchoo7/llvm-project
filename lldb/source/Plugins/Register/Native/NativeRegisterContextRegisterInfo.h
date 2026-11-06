//===-- NativeRegisterContextRegisterInfo.h ---------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_REGISTER_NATIVE_NATIVEREGISTERCONTEXTREGISTERINFO_H
#define LLDB_SOURCE_PLUGINS_REGISTER_NATIVE_NATIVEREGISTERCONTEXTREGISTERINFO_H

#include <memory>

#include "lldb/Host/common/NativeRegisterContext.h"
#include "lldb/Register/RegisterInfoProvider.h"

namespace lldb_private {
class NativeRegisterContextRegisterInfo : public NativeRegisterContext {
public:
  ///
  /// Construct a NativeRegisterContextRegisterInfo, taking ownership
  /// of the register_info_interface pointer.
  ///
  NativeRegisterContextRegisterInfo(
      NativeThreadProtocol &thread,
      RegisterInfoProvider *register_info_interface);

  uint32_t GetRegisterCount() const override;
  uint32_t GetRegisterValueOffset(uint32_t index) const override;

  uint32_t GetUserRegisterCount() const override;

  const RegisterInfo *GetRegisterInfoAtIndex(uint32_t reg_index) const override;

  const RegisterInfoProvider &GetRegisterInfoProvider() const;

  // Invalidate cached values in register context data structures.
  virtual void InvalidateAllRegisters() {}

protected:
  std::unique_ptr<RegisterInfoProvider> m_register_info_interface_up;
};
} // namespace lldb_private
#endif
