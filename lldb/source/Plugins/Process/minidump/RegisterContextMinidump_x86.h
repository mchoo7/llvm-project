//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_PLUGINS_PROCESS_MINIDUMP_REGISTERCONTEXTMINIDUMP_X86_H
#define LLDB_PLUGINS_PROCESS_MINIDUMP_REGISTERCONTEXTMINIDUMP_X86_H
#include "lldb/Register/Common/RegisterInfo_x86.h"
#include "lldb/Target/RegisterContext.h"
namespace lldb_private::minidump {
RegisterModel CreateMinidumpX86RegisterModel(const ArchSpec &arch);
llvm::Expected<RegisterValue>
ReadMinidumpX86Register(const RegisterInfoProvider &info,
                        llvm::ArrayRef<uint8_t> context,
                        const RegisterInfo &reg);
class RegisterContextMinidump_x86 : public RegisterContext {
public:
  RegisterContextMinidump_x86(Thread &thread, const ArchSpec &arch,
                              llvm::ArrayRef<uint8_t> context);
  void InvalidateAllRegisters() override {}
  size_t GetRegisterCount() override { return m_info.GetRegisterCount(); }
  const RegisterInfo *GetRegisterInfoAtIndex(size_t index) override {
    return index < m_info.GetRegisterCount() ? m_info.GetRegisterInfo() + index
                                             : nullptr;
  }
  size_t GetRegisterSetCount() override { return m_info.GetRegisterSetCount(); }
  const RegisterSet *GetRegisterSet(size_t index) override {
    return m_info.GetRegisterSet(index);
  }
  bool ReadRegister(const RegisterInfo *reg, RegisterValue &value) override;
  bool WriteRegister(const RegisterInfo *, const RegisterValue &) override {
    return false;
  }
  bool ReadAllRegisterValues(lldb::WritableDataBufferSP &) override {
    return false;
  }
  bool WriteAllRegisterValues(const lldb::DataBufferSP &) override {
    return false;
  }
  bool HardwareSingleStep(bool) override { return false; }

private:
  RegisterInfo_x86 m_info;
  std::vector<uint8_t> m_context;
};
} // namespace lldb_private::minidump
#endif
