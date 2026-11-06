//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_REGISTERLAYOUT_H
#define LLDB_REGISTER_REGISTERLAYOUT_H

#include "lldb/Register/RegisterDescription.h"
#include <optional>

namespace lldb_private {

using RegisterBankID = uint32_t;

/// A named field in a concrete storage format, independent of table order.
struct RegisterStorageField {
  const char *name;
  uint32_t byte_size;
  uint32_t byte_offset;
};

struct RegisterBank {
  RegisterBankID id;
  uint64_t byte_size;
};

/// Offsets are bytes in the source bank and in the encoded register value.
struct RegisterPiece {
  RegisterBankID bank;
  uint64_t byte_offset;
  uint32_t byte_size;
  uint32_t value_offset = 0;
};

struct RegisterLocation {
  enum Kind { Stored, Constant, Unavailable } kind = Unavailable;
  std::vector<RegisterPiece> pieces;
  std::vector<uint8_t> constant;

  /// Unmapped value bytes are zero (for example inactive vector lanes).
  bool zero_fill = false;
};

/// A concrete saved-register format, independent of native state acquisition.
class RegisterLayout {
public:
  explicit RegisterLayout(lldb::ByteOrder byte_order)
      : m_byte_order(byte_order) {}

  llvm::Error AddBank(RegisterBankID bank, uint64_t byte_size);
  llvm::Error Add(RegisterID id, RegisterLocation location);
  const RegisterLocation *Find(RegisterID id) const;
  const RegisterBank *FindBank(RegisterBankID id) const;
  lldb::ByteOrder GetByteOrder() const { return m_byte_order; }
  llvm::Error Validate(const RegisterDescription &description) const;

  /// Import an existing flat format by name, keeping identities independent of
  /// its table ordering. Formats with separate banks should construct them
  /// explicitly instead.
  static llvm::Expected<RegisterLayout>
  FromLegacy(const RegisterDescription &description,
             llvm::ArrayRef<RegisterInfo> registers, uint64_t byte_size,
             lldb::ByteOrder byte_order);

private:
  lldb::ByteOrder m_byte_order;
  std::map<RegisterBankID, RegisterBank> m_banks;
  std::map<RegisterID, RegisterLocation> m_locations;
};

/// The same finalized value/layout pair is used by every architecture.
struct RegisterModel {
  std::shared_ptr<const RegisterDescription> description;
  RegisterLayout layout;
  uint32_t user_register_count = LLDB_INVALID_REGNUM;
};

} // namespace lldb_private

#endif
