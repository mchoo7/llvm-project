//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_REGISTERDESCRIPTION_H
#define LLDB_REGISTER_REGISTERDESCRIPTION_H

#include "lldb/Utility/RegisterInfo.h"
#include "lldb/lldb-defines.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"
#include <array>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lldb_private {

/// An architecture identity, independent of an exposed table index or offset.
using RegisterID = uint32_t;

struct RegisterDescriptor {
  RegisterID id = LLDB_INVALID_REGNUM;
  std::string name;
  std::string alt_name;
  uint32_t byte_size = 0;
  lldb::Encoding encoding = lldb::eEncodingUint;
  lldb::Format format = lldb::eFormatHex;
  std::array<uint32_t, lldb::kNumRegisterKinds> numbers;
  std::vector<RegisterID> value_registers;
  std::vector<RegisterID> invalidate_registers;
  /// Least-significant byte position within a single parent logical value.
  uint32_t value_byte_offset = 0;
  const RegisterType *type = nullptr;
  /// Writing this value clears the remaining high bytes of its parent.
  RegisterID zero_extend_parent = LLDB_INVALID_REGNUM;
  /// Little-endian bytes of an architectural constant. Empty for ordinary
  /// registers; zero registers need no saved-state bank.
  std::vector<uint8_t> constant_value;

  RegisterDescriptor() { numbers.fill(LLDB_INVALID_REGNUM); }
};

struct RegisterGroup {
  std::string name;
  std::string short_name;
  std::vector<RegisterID> registers;
};

/// Finalized, owning metadata. It contains no saved-register storage layout.
class RegisterDescription {
public:
  /// Own every type node referenced by a description, including enum fields.
  using OwnedTypes = std::vector<std::shared_ptr<const RegisterType>>;
  static llvm::Expected<RegisterDescription>
  Create(std::vector<RegisterDescriptor> registers,
         std::vector<RegisterGroup> groups = {}, OwnedTypes types = {});

  /// Migration boundary: copy metadata, deliberately discarding byte_offset.
  static llvm::Expected<RegisterDescription>
  FromLegacy(llvm::ArrayRef<RegisterInfo> registers,
             llvm::ArrayRef<RegisterSet> groups = {});

  llvm::ArrayRef<RegisterDescriptor> GetRegisters() const {
    return m_registers;
  }
  llvm::ArrayRef<RegisterGroup> GetGroups() const { return m_groups; }
  llvm::ArrayRef<std::shared_ptr<const RegisterType>> GetOwnedTypes() const {
    return m_owned_types;
  }
  const RegisterDescriptor *Find(RegisterID id) const;
  const RegisterDescriptor *Find(llvm::StringRef name) const;

private:
  OwnedTypes m_owned_types;
  std::vector<RegisterDescriptor> m_registers;
  std::vector<RegisterGroup> m_groups;
  std::map<RegisterID, size_t> m_ids;
  std::map<std::string, size_t, std::less<>> m_names;
};

class RegisterLayout;

/// An owning compatibility view for existing context and protocol interfaces.
/// All metadata comes from the description. Storage offsets remain in the
/// layout.
class RegisterInfoView {
public:
  RegisterInfoView() = default;
  RegisterInfoView(RegisterInfoView &&) = default;
  RegisterInfoView &operator=(RegisterInfoView &&) = default;
  RegisterInfoView(const RegisterInfoView &) = delete;
  RegisterInfoView &operator=(const RegisterInfoView &) = delete;
  static llvm::Expected<RegisterInfoView>
  Create(std::shared_ptr<const RegisterDescription> description,
         const RegisterLayout &layout, llvm::ArrayRef<RegisterID> order = {});

  llvm::ArrayRef<RegisterInfo> GetRegisters() const { return m_registers; }
  llvm::ArrayRef<RegisterSet> GetGroups() const { return m_groups; }
  const RegisterDescription &GetDescription() const { return *m_description; }

  /// Keep compatibility-record addresses stable when only value sizes change.
  void Replace(RegisterInfoView view);

private:
  std::shared_ptr<const RegisterDescription> m_description;
  std::vector<RegisterInfo> m_registers;
  std::vector<RegisterSet> m_groups;
  std::vector<std::vector<uint32_t>> m_value_registers;
  std::vector<std::vector<uint32_t>> m_invalidate_registers;
  std::vector<std::vector<uint32_t>> m_group_indices;
};

} // namespace lldb_private

#endif
