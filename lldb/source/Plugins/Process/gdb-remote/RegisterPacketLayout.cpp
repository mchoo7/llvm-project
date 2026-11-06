//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterPacketLayout.h"
#include "lldb/lldb-defines.h"
#include <functional>
#include <limits>
#include <map>
using namespace lldb_private;
using namespace lldb_private::process_gdb_remote;
llvm::Expected<RegisterPacketLayout>
RegisterPacketLayout::Create(llvm::ArrayRef<RegisterInfo> registers,
                             llvm::ArrayRef<uint32_t> value_offsets) {
  if (registers.size() != value_offsets.size())
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "missing register alias offsets");
  RegisterPacketLayout result;
  result.m_registers.assign(registers.begin(), registers.end());
  result.m_primary.resize(registers.size(), true);
  result.m_values.resize(registers.size());
  result.m_invalidates.resize(registers.size());
  std::map<uint32_t, uint32_t> indices;
  for (size_t i = 0; i < registers.size(); ++i) {
    if (!registers[i].byte_size)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "empty register value");
    uint32_t number = registers[i].kinds[lldb::eRegisterKindLLDB];
    if (number != LLDB_INVALID_REGNUM && !indices.emplace(number, i).second)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "duplicate context register number");
  }
  std::vector<uint32_t> parent(registers.size(), LLDB_INVALID_REGNUM);
  for (size_t i = 0; i < registers.size(); ++i) {
    const auto &reg = registers[i];
    if (reg.value_regs && reg.value_regs[0] != LLDB_INVALID_REGNUM &&
        reg.value_regs[1] == LLDB_INVALID_REGNUM) {
      auto it = indices.find(reg.value_regs[0]);
      if (it != indices.end()) {
        parent[i] = it->second;
        result.m_primary[i] = false;
      }
    }
    if (result.m_primary[i]) {
      if (reg.byte_size >
          std::numeric_limits<uint32_t>::max() - result.m_byte_size)
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "register packet is too large");
      result.m_registers[i].byte_offset = result.m_byte_size;
      result.m_byte_size += reg.byte_size;
    }
    for (auto refs :
         {std::make_pair(reg.value_regs, &result.m_values[i]),
          std::make_pair(reg.invalidate_regs, &result.m_invalidates[i])}) {
      if (!refs.first)
        continue;
      for (auto *number = refs.first; *number != LLDB_INVALID_REGNUM; ++number)
        if (auto it = indices.find(*number); it != indices.end())
          refs.second->push_back(it->second);
      if (!refs.second->empty())
        refs.second->push_back(LLDB_INVALID_REGNUM);
    }
    result.m_registers[i].value_regs =
        result.m_values[i].empty() ? nullptr : result.m_values[i].data();
    result.m_registers[i].invalidate_regs =
        result.m_invalidates[i].empty() ? nullptr
                                        : result.m_invalidates[i].data();
  }
  std::vector<uint8_t> state(registers.size(), 0);
  std::function<llvm::Error(size_t)> resolve = [&](size_t i) -> llvm::Error {
    if (state[i] == 2)
      return llvm::Error::success();
    if (state[i] == 1)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "cyclic register aliases");
    state[i] = 1;
    if (!result.m_primary[i]) {
      size_t p = parent[i];
      if (auto error = resolve(p))
        return error;
      if (value_offsets[i] > registers[p].byte_size ||
          registers[i].byte_size > registers[p].byte_size - value_offsets[i])
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "register alias exceeds its parent");
      result.m_registers[i].byte_offset =
          result.m_registers[p].byte_offset + value_offsets[i];
    }
    state[i] = 2;
    return llvm::Error::success();
  };
  for (size_t i = 0; i < registers.size(); ++i)
    if (auto error = resolve(i))
      return std::move(error);
  return result;
}
