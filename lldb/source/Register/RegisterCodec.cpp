//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/RegisterCodec.h"
#include "lldb/Utility/Status.h"
#include <algorithm>
#include <cstring>

using namespace lldb_private;

namespace {
template <typename Bank>
llvm::Error CheckBanks(const RegisterLayout &layout,
                       const RegisterLocation &location,
                       llvm::ArrayRef<Bank> banks) {
  for (size_t i = 0; i != banks.size(); ++i) {
    for (size_t j = 0; j != i; ++j)
      if (banks[i].bank == banks[j].bank)
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "duplicate register bank data");
    const auto *format = layout.FindBank(banks[i].bank);
    if (!format)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "truncated or unknown register bank");
  }
  for (const auto &piece : location.pieces) {
    auto bank = std::find_if(banks.begin(), banks.end(), [&](const Bank &bank) {
      return bank.bank == piece.bank;
    });
    if (bank == banks.end())
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "missing register bank");
    if (piece.byte_offset > bank->bytes.size() ||
        piece.byte_size > bank->bytes.size() - piece.byte_offset)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "truncated register bank");
  }
  return llvm::Error::success();
}

RegisterInfo ValueInfo(const RegisterDescriptor &reg) {
  RegisterInfo info{};
  info.name = reg.name.c_str();
  info.byte_size = reg.byte_size;
  info.encoding = reg.encoding;
  info.format = reg.format;
  info.register_type = reg.type;
  return info;
}
} // namespace

llvm::Expected<RegisterValue>
RegisterCodec::Read(const RegisterDescription &description,
                    const RegisterLayout &layout, RegisterID id,
                    llvm::ArrayRef<RegisterData> banks) {
  if (llvm::Error error = layout.Validate(description))
    return std::move(error);
  const auto *reg = description.Find(id);
  const auto *location = layout.Find(id);
  if (!reg || (reg->constant_value.empty() &&
               (!location || location->kind == RegisterLocation::Unavailable)))
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "register is unavailable");
  std::vector<uint8_t> bytes(reg->byte_size);
  if (!reg->constant_value.empty()) {
    bytes = reg->constant_value;
    if (layout.GetByteOrder() == lldb::eByteOrderBig)
      std::reverse(bytes.begin(), bytes.end());
  } else if (location->kind == RegisterLocation::Constant) {
    bytes = location->constant;
  } else {
    if (llvm::Error error = CheckBanks(layout, *location, banks))
      return std::move(error);
    for (const auto &piece : location->pieces)
      for (const auto &bank : banks)
        if (bank.bank == piece.bank)
          std::memcpy(bytes.data() + piece.value_offset,
                      bank.bytes.data() + piece.byte_offset, piece.byte_size);
  }
  RegisterValue result;
  Status error;
  result.SetFromMemoryData(ValueInfo(*reg), bytes.data(), bytes.size(),
                           layout.GetByteOrder(), error);
  if (error.Fail())
    return llvm::createStringError(llvm::inconvertibleErrorCode(), "%s",
                                   error.AsCString());
  return result;
}

llvm::Error RegisterCodec::Write(const RegisterDescription &description,
                                 const RegisterLayout &layout, RegisterID id,
                                 const RegisterValue &value,
                                 llvm::ArrayRef<MutableRegisterData> banks) {
  if (llvm::Error error = layout.Validate(description))
    return error;
  const auto *reg = description.Find(id);
  const auto *location = layout.Find(id);
  if (!reg || !reg->constant_value.empty() || !location ||
      location->kind != RegisterLocation::Stored)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "register is unavailable or read-only");
  if (llvm::Error error = CheckBanks(layout, *location, banks))
    return error;
  std::vector<uint8_t> bytes(reg->byte_size);
  Status error;
  if (value.GetAsMemoryData(ValueInfo(*reg), bytes.data(), bytes.size(),
                            layout.GetByteOrder(), error) != bytes.size())
    return llvm::createStringError(llvm::inconvertibleErrorCode(), "%s",
                                   error.AsCString());
  if (location->zero_fill) {
    std::vector<bool> stored(reg->byte_size, false);
    for (const auto &piece : location->pieces)
      for (uint32_t i = 0; i < piece.byte_size; ++i)
        stored[piece.value_offset + i] = true;
    for (size_t i = 0; i < stored.size(); ++i)
      if (!stored[i] && bytes[i])
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "cannot enable inactive register lanes");
  }
  if (reg->zero_extend_parent != LLDB_INVALID_REGNUM) {
    const auto *parent = description.Find(reg->zero_extend_parent);
    const auto *parent_location = layout.Find(reg->zero_extend_parent);
    if (!parent || !parent_location ||
        parent_location->kind != RegisterLocation::Stored)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "zero-extension parent is unavailable");
    if (llvm::Error error = CheckBanks(layout, *parent_location, banks))
      return error;
    std::vector<uint8_t> extended(parent->byte_size, 0);
    size_t offset = layout.GetByteOrder() == lldb::eByteOrderBig
                        ? parent->byte_size - reg->byte_size
                        : 0;
    std::copy(bytes.begin(), bytes.end(), extended.begin() + offset);
    bytes = std::move(extended);
    location = parent_location;
  }
  for (const auto &piece : location->pieces)
    for (const auto &bank : banks)
      if (bank.bank == piece.bank)
        std::memcpy(bank.bytes.data() + piece.byte_offset,
                    bytes.data() + piece.value_offset, piece.byte_size);
  return llvm::Error::success();
}
