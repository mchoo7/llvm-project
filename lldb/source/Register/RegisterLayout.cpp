//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/RegisterLayout.h"
#include <algorithm>

using namespace lldb_private;

llvm::Error RegisterLayout::AddBank(RegisterBankID id, uint64_t byte_size) {
  if (!m_banks.emplace(id, RegisterBank{id, byte_size}).second)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "duplicate register bank");
  return llvm::Error::success();
}

llvm::Error RegisterLayout::Add(RegisterID id, RegisterLocation location) {
  if (id == LLDB_INVALID_REGNUM ||
      !m_locations.emplace(id, std::move(location)).second)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "invalid or duplicate register location");
  return llvm::Error::success();
}

const RegisterLocation *RegisterLayout::Find(RegisterID id) const {
  auto it = m_locations.find(id);
  return it == m_locations.end() ? nullptr : &it->second;
}

const RegisterBank *RegisterLayout::FindBank(RegisterBankID id) const {
  auto it = m_banks.find(id);
  return it == m_banks.end() ? nullptr : &it->second;
}

llvm::Error
RegisterLayout::Validate(const RegisterDescription &description) const {
  if (m_byte_order != lldb::eByteOrderLittle &&
      m_byte_order != lldb::eByteOrderBig)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "invalid register storage byte order");
  for (const auto &[id, location] : m_locations) {
    const auto *reg = description.Find(id);
    if (!reg)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "unknown register location identity");
    if (location.kind != RegisterLocation::Stored) {
      if (location.zero_fill || !location.pieces.empty() ||
          (location.kind == RegisterLocation::Constant &&
           location.constant.size() != reg->byte_size) ||
          (location.kind == RegisterLocation::Unavailable &&
           !location.constant.empty()))
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "invalid non-storage register location");
      continue;
    }
    if (!location.constant.empty())
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "stored register has a constant value");
    std::vector<bool> covered(reg->byte_size, false);
    for (const auto &piece : location.pieces) {
      const auto *bank = FindBank(piece.bank);
      if (!bank || !piece.byte_size || piece.byte_offset > bank->byte_size ||
          piece.byte_size > bank->byte_size - piece.byte_offset ||
          piece.value_offset > reg->byte_size ||
          piece.byte_size > reg->byte_size - piece.value_offset)
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "register piece out of bounds");
      for (uint32_t i = 0; i != piece.byte_size; ++i) {
        if (covered[piece.value_offset + i])
          return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                         "overlapping register pieces");
        covered[piece.value_offset + i] = true;
      }
    }
    if (!location.zero_fill &&
        std::find(covered.begin(), covered.end(), false) != covered.end())
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "incomplete register storage mapping");
  }
  return llvm::Error::success();
}

llvm::Expected<RegisterLayout>
RegisterLayout::FromLegacy(const RegisterDescription &description,
                           llvm::ArrayRef<RegisterInfo> registers,
                           uint64_t byte_size, lldb::ByteOrder byte_order) {
  RegisterLayout result(byte_order);
  if (llvm::Error error = result.AddBank(0, byte_size))
    return std::move(error);
  for (const auto &input : registers) {
    const auto *reg = input.name ? description.Find(input.name) : nullptr;
    if (!reg || reg->byte_size != input.byte_size)
      return llvm::createStringError(
          llvm::inconvertibleErrorCode(),
          "layout does not match register description");
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({0, input.byte_offset, input.byte_size, 0});

    if (llvm::Error error = result.Add(reg->id, std::move(location)))
      return std::move(error);
  }
  if (llvm::Error error = result.Validate(description))
    return std::move(error);
  return result;
}
