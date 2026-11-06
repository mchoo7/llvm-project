//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_PLUGINS_PROCESS_GDB_REMOTE_REGISTERPACKETLAYOUT_H
#define LLDB_PLUGINS_PROCESS_GDB_REMOTE_REGISTERPACKETLAYOUT_H
#include "lldb/Utility/RegisterInfo.h"
#include "llvm/Support/Error.h"
#include <vector>
namespace lldb_private::process_gdb_remote {
/// A wire projection of visible registers. Native storage offsets are ignored.
class RegisterPacketLayout {
public:
  RegisterPacketLayout() = default;
  RegisterPacketLayout(RegisterPacketLayout &&) = default;
  RegisterPacketLayout &operator=(RegisterPacketLayout &&) = default;
  RegisterPacketLayout(const RegisterPacketLayout &) = delete;
  RegisterPacketLayout &operator=(const RegisterPacketLayout &) = delete;
  static llvm::Expected<RegisterPacketLayout>
  Create(llvm::ArrayRef<RegisterInfo> registers,
         llvm::ArrayRef<uint32_t> value_offsets);
  llvm::ArrayRef<RegisterInfo> GetRegisters() const { return m_registers; }
  bool IsPrimary(size_t index) const { return m_primary[index]; }
  uint32_t GetByteSize() const { return m_byte_size; }

private:
  std::vector<RegisterInfo> m_registers;
  std::vector<std::vector<uint32_t>> m_values;
  std::vector<std::vector<uint32_t>> m_invalidates;
  std::vector<bool> m_primary;
  uint32_t m_byte_size = 0;
};
} // namespace lldb_private::process_gdb_remote
#endif
