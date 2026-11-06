//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/RegisterDescription.h"
#include "lldb/Register/RegisterLayout.h"
#include <algorithm>
#include <iterator>
#include <set>

using namespace lldb_private;

llvm::Expected<RegisterDescription>
RegisterDescription::Create(std::vector<RegisterDescriptor> registers,
                            std::vector<RegisterGroup> groups,
                            OwnedTypes types) {
  RegisterDescription result;
  result.m_owned_types = std::move(types);
  result.m_registers = std::move(registers);
  result.m_groups = std::move(groups);
  for (size_t i = 0; i != result.m_registers.size(); ++i) {
    const auto &reg = result.m_registers[i];
    if (reg.id == LLDB_INVALID_REGNUM || reg.name.empty() || !reg.byte_size ||
        (!reg.constant_value.empty() &&
         reg.constant_value.size() != reg.byte_size))
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "invalid register description");
    if (!result.m_ids.emplace(reg.id, i).second ||
        !result.m_names.emplace(reg.name, i).second)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "duplicate register identity or name");
  }
  for (const auto &reg : result.m_registers) {
    if (reg.zero_extend_parent != LLDB_INVALID_REGNUM) {
      const auto *parent = result.Find(reg.zero_extend_parent);
      if (!parent || parent->id == reg.id || parent->byte_size <= reg.byte_size)
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "invalid zero-extension parent");
    }
    for (auto refs : {llvm::ArrayRef<RegisterID>(reg.value_registers),
                      llvm::ArrayRef<RegisterID>(reg.invalidate_registers)})
      for (RegisterID id : refs)
        if (!result.Find(id))
          return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                         "unknown register relationship");
  }
  for (const auto &group : result.m_groups) {
    std::set<RegisterID> seen;
    for (RegisterID id : group.registers)
      if (!result.Find(id) || !seen.insert(id).second)
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "invalid register group member");
  }
  return result;
}

void RegisterInfoView::Replace(RegisterInfoView view) {
  if (m_registers.size() == view.m_registers.size()) {
    std::copy(view.m_registers.begin(), view.m_registers.end(),
              m_registers.begin());
    view.m_registers = std::move(m_registers);
  }
  if (m_groups.size() == view.m_groups.size()) {
    std::copy(view.m_groups.begin(), view.m_groups.end(), m_groups.begin());
    view.m_groups = std::move(m_groups);
  }
  *this = std::move(view);
}

llvm::Expected<RegisterDescription>
RegisterDescription::FromLegacy(llvm::ArrayRef<RegisterInfo> registers,
                                llvm::ArrayRef<RegisterSet> groups) {
  std::vector<RegisterDescriptor> descriptions;
  auto get_id = [&](size_t index) {
    uint32_t id = registers[index].kinds[lldb::eRegisterKindLLDB];
    return id == LLDB_INVALID_REGNUM ? uint32_t(index) : id;
  };
  for (size_t i = 0; i != registers.size(); ++i) {
    const RegisterInfo &input = registers[i];
    RegisterDescriptor reg;
    reg.id = get_id(i);
    reg.name = input.name ? input.name : "";
    reg.alt_name = input.alt_name ? input.alt_name : "";
    reg.byte_size = input.byte_size;
    reg.encoding = input.encoding;
    reg.format = input.format;
    std::copy(std::begin(input.kinds), std::end(input.kinds),
              reg.numbers.begin());
    reg.type = input.register_type;
    for (auto pair :
         {std::make_pair(input.value_regs, &reg.value_registers),
          std::make_pair(input.invalidate_regs, &reg.invalidate_registers)}) {
      if (!pair.first)
        continue;
      for (const uint32_t *ref = pair.first; *ref != LLDB_INVALID_REGNUM;
           ++ref) {
        auto referenced = std::find_if(
            registers.begin(), registers.end(),
            [&](const RegisterInfo &candidate) {
              return candidate.kinds[lldb::eRegisterKindLLDB] == *ref;
            });
        if (referenced == registers.end() && *ref >= registers.size())
          return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                         "register relationship out of range");
        pair.second->push_back(get_id(referenced == registers.end()
                                          ? *ref
                                          : referenced - registers.begin()));
      }
    }
    if (input.value_regs && input.value_regs[0] != LLDB_INVALID_REGNUM &&
        input.value_regs[1] == LLDB_INVALID_REGNUM) {
      auto parent = std::find_if(
          registers.begin(), registers.end(), [&](const RegisterInfo &r) {
            return r.kinds[lldb::eRegisterKindLLDB] == input.value_regs[0];
          });
      if (parent != registers.end() &&
          input.byte_offset >= parent->byte_offset &&
          input.byte_offset - parent->byte_offset <= parent->byte_size &&
          input.byte_size <=
              parent->byte_size - (input.byte_offset - parent->byte_offset))
        reg.value_byte_offset = input.byte_offset - parent->byte_offset;
    }
    descriptions.push_back(std::move(reg));
  }
  std::vector<RegisterGroup> result_groups;
  for (const auto &input : groups) {
    RegisterGroup group{input.name ? input.name : "",
                        input.short_name ? input.short_name : "",
                        {}};
    for (size_t i = 0; i != input.num_registers; ++i) {
      if (!input.registers || input.registers[i] >= registers.size())
        return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                       "register group index out of range");
      group.registers.push_back(get_id(input.registers[i]));
    }
    result_groups.push_back(std::move(group));
  }
  return Create(std::move(descriptions), std::move(result_groups));
}

const RegisterDescriptor *RegisterDescription::Find(RegisterID id) const {
  auto it = m_ids.find(id);
  return it == m_ids.end() ? nullptr : &m_registers[it->second];
}

const RegisterDescriptor *
RegisterDescription::Find(llvm::StringRef name) const {
  auto it = m_names.find(name.str());
  if (it != m_names.end())
    return &m_registers[it->second];
  for (const auto &reg : m_registers)
    if (!reg.alt_name.empty() && reg.alt_name == name)
      return &reg;
  return nullptr;
}

llvm::Expected<RegisterInfoView>
RegisterInfoView::Create(std::shared_ptr<const RegisterDescription> description,
                         const RegisterLayout &layout,
                         llvm::ArrayRef<RegisterID> order) {
  if (!description)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "missing register description");
  if (llvm::Error error = layout.Validate(*description))
    return std::move(error);
  RegisterInfoView result;
  result.m_description = std::move(description);
  std::vector<RegisterID> default_order;
  if (order.empty()) {
    for (const auto &reg : result.m_description->GetRegisters())
      default_order.push_back(reg.id);
    order = default_order;
  }
  std::map<RegisterID, uint32_t> indices;
  for (RegisterID id : order)
    if (!result.m_description->Find(id) ||
        !indices.emplace(id, indices.size()).second)
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "invalid register presentation order");
  result.m_registers.reserve(order.size());
  result.m_value_registers.resize(order.size());
  result.m_invalidate_registers.resize(order.size());
  for (size_t i = 0; i != order.size(); ++i) {
    const auto &reg = *result.m_description->Find(order[i]);
    RegisterInfo info{};
    info.name = reg.name.c_str();
    info.alt_name = reg.alt_name.empty() ? nullptr : reg.alt_name.c_str();
    info.byte_size = reg.byte_size;
    // Physical offsets are obtained from RegisterLayout, never this metadata
    // view.
    info.encoding = reg.encoding;
    info.format = reg.format;
    std::copy(reg.numbers.begin(), reg.numbers.end(), std::begin(info.kinds));
    if (info.kinds[lldb::eRegisterKindLLDB] == LLDB_INVALID_REGNUM)
      info.kinds[lldb::eRegisterKindLLDB] = i;
    info.register_type = reg.type;
    for (auto pair :
         {std::make_pair(&reg.value_registers, &result.m_value_registers[i]),
          std::make_pair(&reg.invalidate_registers,
                         &result.m_invalidate_registers[i])}) {
      for (RegisterID id : *pair.first) {
        auto it = indices.find(id);
        if (it == indices.end())
          return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                         "register relationship not exposed");
        const auto &target = *result.m_description->Find(id);
        uint32_t number = target.numbers[lldb::eRegisterKindLLDB];
        pair.second->push_back(number == LLDB_INVALID_REGNUM ? it->second
                                                             : number);
      }
      if (!pair.first->empty())
        pair.second->push_back(LLDB_INVALID_REGNUM);
    }
    info.value_regs = reg.value_registers.empty()
                          ? nullptr
                          : result.m_value_registers[i].data();
    info.invalidate_regs = reg.invalidate_registers.empty()
                               ? nullptr
                               : result.m_invalidate_registers[i].data();
    result.m_registers.push_back(info);
  }
  result.m_group_indices.reserve(result.m_description->GetGroups().size());
  for (const auto &group : result.m_description->GetGroups()) {
    result.m_group_indices.emplace_back();
    auto &members = result.m_group_indices.back();
    for (RegisterID id : group.registers) {
      auto it = indices.find(id);
      if (it != indices.end())
        members.push_back(it->second);
    }
    result.m_groups.push_back({group.name.c_str(), group.short_name.c_str(),
                               members.size(), members.data()});
  }
  return result;
}
