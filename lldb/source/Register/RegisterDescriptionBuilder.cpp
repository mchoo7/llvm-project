//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/RegisterDescriptionBuilder.h"
#include "llvm/ADT/STLExtras.h"
#include <cstring>
using namespace lldb;
using namespace lldb_private;

RegisterDescriptionBuilder::RegisterDescriptionBuilder(
    const RegisterDescriptionBuilder &info)
    : m_regs(info.m_regs), m_architecture_ids(info.m_architecture_ids),
      m_sets(info.m_sets), m_set_reg_nums(info.m_set_reg_nums),
      m_value_regs_map(info.m_value_regs_map),
      m_invalidate_regs_map(info.m_invalidate_regs_map),
      m_value_reg_offset_map(info.m_value_reg_offset_map),
      m_reg_data_byte_size(info.m_reg_data_byte_size),
      m_finalized(info.m_finalized),
      m_is_reconfigurable(info.m_is_reconfigurable) {
  if (!m_finalized)
    return;
  for (size_t i = 0; i < m_sets.size(); ++i)
    m_sets[i].m_set.registers = m_set_reg_nums[i].data();
  for (size_t i = 0; i < m_regs.size(); ++i) {
    auto value = m_value_regs_map.find(i);
    auto invalidate = m_invalidate_regs_map.find(i);
    m_regs[i].value_regs =
        value == m_value_regs_map.end() ? nullptr : value->second.data();
    m_regs[i].invalidate_regs = invalidate == m_invalidate_regs_map.end()
                                    ? nullptr
                                    : invalidate->second.data();
  }
}
RegisterDescriptionBuilder &
RegisterDescriptionBuilder::operator=(const RegisterDescriptionBuilder &info) {
  if (this != &info) {
    RegisterDescriptionBuilder copy(info);
    MoveFrom(std::move(copy));
  }
  return *this;
}

RegisterDescriptionBuilder::RegisterDescriptionBuilder(
    RegisterDescriptionBuilder &&info) {
  MoveFrom(std::move(info));
}

RegisterDescriptionBuilder &
RegisterDescriptionBuilder::operator=(RegisterDescriptionBuilder &&info) {
  if (this != &info)
    MoveFrom(std::move(info));
  return *this;
}

void RegisterDescriptionBuilder::MoveFrom(RegisterDescriptionBuilder &&info) {
  m_regs = std::move(info.m_regs);
  m_architecture_ids = std::move(info.m_architecture_ids);
  m_sets = std::move(info.m_sets);
  m_set_reg_nums = std::move(info.m_set_reg_nums);
  m_value_regs_map = std::move(info.m_value_regs_map);
  m_invalidate_regs_map = std::move(info.m_invalidate_regs_map);
  m_value_reg_offset_map = std::move(info.m_value_reg_offset_map);
  m_is_reconfigurable = info.m_is_reconfigurable;

  m_reg_data_byte_size = info.m_reg_data_byte_size;
  m_finalized = info.m_finalized;

  if (m_finalized) {
    const size_t num_sets = m_sets.size();
    for (size_t set = 0; set < num_sets; ++set)
      m_sets[set].m_set.registers = m_set_reg_nums[set].data();
  }

  info.Clear();
}

size_t RegisterDescriptionBuilder::SetRegisterInfo(
    std::vector<RegisterDescriptionBuilder::Register> &&regs,
    const ArchSpec &arch) {
  assert(!m_finalized);

  llvm::StringMap<uint32_t> set_name_to_idx;
  uint32_t next_idx = 0;

  for (auto it : llvm::enumerate(regs)) {
    uint32_t local_regnum = it.index();
    const RegisterDescriptionBuilder::Register &reg = it.value();

    assert(reg.name);
    assert(reg.set_name);

    if (!reg.value_regs.empty())
      m_value_regs_map[local_regnum] = std::move(reg.value_regs);
    if (!reg.invalidate_regs.empty())
      m_invalidate_regs_map[local_regnum] = std::move(reg.invalidate_regs);
    if (reg.value_reg_offset != 0) {
      assert(reg.value_regs.size() == 1);
      m_value_reg_offset_map[local_regnum] = reg.value_reg_offset;
    }

    struct RegisterInfo reg_info{
        reg.name.AsCString(nullptr),
        reg.alt_name.AsCString(nullptr),
        reg.byte_size,
        reg.byte_offset,
        reg.encoding,
        reg.format,
        {reg.regnum_ehframe, reg.regnum_dwarf, reg.regnum_generic,
         reg.regnum_remote, local_regnum},
        // value_regs and invalidate_regs are filled by Finalize()
        nullptr,
        nullptr,
        reg.register_type};

    m_regs.push_back(reg_info);
    m_architecture_ids.push_back(reg.id);

    uint32_t set_idx;
    if (!set_name_to_idx.contains(reg.set_name)) {
      set_idx = next_idx;

      set_name_to_idx.insert({reg.set_name, next_idx++});
      m_set_reg_nums.resize(m_set_reg_nums.size() + 1);
      m_sets.push_back(
          {reg.set_name.GetStringRef().str(), std::string(), 0, nullptr});
    } else {
      set_idx = set_name_to_idx.lookup(reg.set_name);
    }

    assert(set_idx < m_sets.size());
    assert(set_idx < m_set_reg_nums.size());
    m_set_reg_nums[set_idx].push_back(local_regnum);
  }

  Finalize(arch);
  return m_regs.size();
}

void RegisterDescriptionBuilder::Finalize(const ArchSpec &arch) {
  if (m_finalized)
    return;

  m_finalized = true;
  const size_t num_sets = m_sets.size();
  for (size_t set = 0; set < num_sets; ++set) {
    assert(m_sets.size() == m_set_reg_nums.size());
    m_sets[set].m_set.num_registers = m_set_reg_nums[set].size();
    m_sets[set].m_set.registers = m_set_reg_nums[set].data();
  }

  // make sure value_regs are terminated with LLDB_INVALID_REGNUM

  for (reg_to_regs_map::iterator pos = m_value_regs_map.begin(),
                                 end = m_value_regs_map.end();
       pos != end; ++pos) {
    if (pos->second.back() != LLDB_INVALID_REGNUM)
      pos->second.push_back(LLDB_INVALID_REGNUM);
  }

  // Now update all value_regs with each register info as needed
  const size_t num_regs = m_regs.size();
  for (size_t i = 0; i < num_regs; ++i) {
    if (auto it = m_value_regs_map.find(i); it != m_value_regs_map.end())
      m_regs[i].value_regs = it->second.data();
    else
      m_regs[i].value_regs = nullptr;
  }

  // Expand all invalidation dependencies
  for (reg_to_regs_map::iterator pos = m_invalidate_regs_map.begin(),
                                 end = m_invalidate_regs_map.end();
       pos != end; ++pos) {
    const uint32_t reg_num = pos->first;

    if (m_regs[reg_num].value_regs) {
      reg_num_collection extra_invalid_regs;
      for (const uint32_t invalidate_reg_num : pos->second) {
        reg_to_regs_map::iterator invalidate_pos =
            m_invalidate_regs_map.find(invalidate_reg_num);
        if (invalidate_pos != m_invalidate_regs_map.end()) {
          for (const uint32_t concrete_invalidate_reg_num :
               invalidate_pos->second) {
            if (concrete_invalidate_reg_num != reg_num)
              extra_invalid_regs.push_back(concrete_invalidate_reg_num);
          }
        }
      }
      pos->second.insert(pos->second.end(), extra_invalid_regs.begin(),
                         extra_invalid_regs.end());
    }
  }

  // sort and unique all invalidate registers and make sure each is terminated
  // with LLDB_INVALID_REGNUM
  for (reg_to_regs_map::iterator pos = m_invalidate_regs_map.begin(),
                                 end = m_invalidate_regs_map.end();
       pos != end; ++pos) {
    if (pos->second.size() > 1) {
      llvm::sort(pos->second);
      pos->second.erase(llvm::unique(pos->second), pos->second.end());
    }
    assert(!pos->second.empty());
    if (pos->second.back() != LLDB_INVALID_REGNUM)
      pos->second.push_back(LLDB_INVALID_REGNUM);
  }

  // Now update all invalidate_regs with each register info as needed
  for (size_t i = 0; i < num_regs; ++i) {
    if (auto it = m_invalidate_regs_map.find(i);
        it != m_invalidate_regs_map.end())
      m_regs[i].invalidate_regs = it->second.data();
    else
      m_regs[i].invalidate_regs = nullptr;
  }

  // Check if we need to automatically set the generic registers in case they
  // weren't set
  bool generic_regs_specified = false;
  for (const auto &reg : m_regs) {
    if (reg.kinds[eRegisterKindGeneric] != LLDB_INVALID_REGNUM) {
      generic_regs_specified = true;
      break;
    }
  }

  if (!generic_regs_specified) {
    switch (arch.GetMachine()) {
    case llvm::Triple::aarch64:
    case llvm::Triple::aarch64_32:
    case llvm::Triple::aarch64_be:
      for (auto &reg : m_regs) {
        if (strcmp(reg.name, "pc") == 0)
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_PC;
        else if ((strcmp(reg.name, "fp") == 0) ||
                 (strcmp(reg.name, "x29") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
        else if ((strcmp(reg.name, "lr") == 0) ||
                 (strcmp(reg.name, "x30") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_RA;
        else if ((strcmp(reg.name, "sp") == 0) ||
                 (strcmp(reg.name, "x31") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_SP;
        else if (strcmp(reg.name, "cpsr") == 0)
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FLAGS;
      }
      break;

    case llvm::Triple::arm:
    case llvm::Triple::armeb:
    case llvm::Triple::thumb:
    case llvm::Triple::thumbeb:
      for (auto &reg : m_regs) {
        if ((strcmp(reg.name, "pc") == 0) || (strcmp(reg.name, "r15") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_PC;
        else if ((strcmp(reg.name, "sp") == 0) ||
                 (strcmp(reg.name, "r13") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_SP;
        else if ((strcmp(reg.name, "lr") == 0) ||
                 (strcmp(reg.name, "r14") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_RA;
        else if ((strcmp(reg.name, "r7") == 0) &&
                 arch.GetTriple().getVendor() == llvm::Triple::Apple)
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
        else if ((strcmp(reg.name, "r11") == 0) &&
                 arch.GetTriple().getVendor() != llvm::Triple::Apple)
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
        else if (strcmp(reg.name, "fp") == 0)
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
        else if (strcmp(reg.name, "cpsr") == 0)
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FLAGS;
      }
      break;

    case llvm::Triple::x86:
      for (auto &reg : m_regs) {
        if ((strcmp(reg.name, "eip") == 0) || (strcmp(reg.name, "pc") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_PC;
        else if ((strcmp(reg.name, "esp") == 0) ||
                 (strcmp(reg.name, "sp") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_SP;
        else if ((strcmp(reg.name, "ebp") == 0) ||
                 (strcmp(reg.name, "fp") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
        else if ((strcmp(reg.name, "eflags") == 0) ||
                 (strcmp(reg.name, "flags") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FLAGS;
      }
      break;

    case llvm::Triple::x86_64:
      for (auto &reg : m_regs) {
        if ((strcmp(reg.name, "rip") == 0) || (strcmp(reg.name, "pc") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_PC;
        else if ((strcmp(reg.name, "rsp") == 0) ||
                 (strcmp(reg.name, "sp") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_SP;
        else if ((strcmp(reg.name, "rbp") == 0) ||
                 (strcmp(reg.name, "fp") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
        else if ((strcmp(reg.name, "rflags") == 0) ||
                 (strcmp(reg.name, "eflags") == 0) ||
                 (strcmp(reg.name, "flags") == 0))
          reg.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FLAGS;
      }
      break;

    default:
      break;
    }
  }

  // At this stage call ConfigureOffsets to calculate register offsets for
  // targets supporting dynamic offset calculation. It also calculates
  // total byte size of register data.
  ConfigureOffsets();

  // Check if register info is reconfigurable
  // AArch64 SVE register set has configurable register sizes, as does the ZA
  // register that SME added (the streaming state of SME reuses the SVE state).
  if (arch.GetTriple().isAArch64()) {
    for (const auto &reg : m_regs) {
      if ((strcmp(reg.name, "vg") == 0) || (strcmp(reg.name, "svg") == 0)) {
        m_is_reconfigurable = true;
        break;
      }
    }
  }
}

void RegisterDescriptionBuilder::ConfigureOffsets() {
  // We are going to create a map between remote (eRegisterKindProcessPlugin)
  // and local (eRegisterKindLLDB) register numbers. This map will give us
  // remote register numbers in increasing order for offset calculation.
  std::map<uint32_t, uint32_t> remote_to_local_regnum_map;
  for (const auto &reg : m_regs)
    remote_to_local_regnum_map[reg.kinds[eRegisterKindProcessPlugin]] =
        reg.kinds[eRegisterKindLLDB];

  // At this stage we manually calculate g/G packet offsets of all primary
  // registers, only if target XML or qRegisterInfo packet did not send
  // an offset explicitly.
  uint32_t reg_offset = 0;
  for (auto const &regnum_pair : remote_to_local_regnum_map) {
    if (m_regs[regnum_pair.second].byte_offset == LLDB_INVALID_INDEX32 &&
        m_regs[regnum_pair.second].value_regs == nullptr) {
      m_regs[regnum_pair.second].byte_offset = reg_offset;

      reg_offset = m_regs[regnum_pair.second].byte_offset +
                   m_regs[regnum_pair.second].byte_size;
    }
  }

  // Now update all value_regs with each register info as needed
  for (auto &reg : m_regs) {
    if (reg.value_regs != nullptr) {
      // Assign a valid offset to all pseudo registers that have only a single
      // parent register in value_regs list, if not assigned by stub.  Pseudo
      // registers with value_regs list populated will share same offset as
      // that of their corresponding parent register.
      if (reg.byte_offset == LLDB_INVALID_INDEX32) {
        uint32_t value_regnum = reg.value_regs[0];
        if (value_regnum != LLDB_INVALID_INDEX32 &&
            reg.value_regs[1] == LLDB_INVALID_INDEX32) {
          reg.byte_offset = GetRegisterInfoAtIndex(value_regnum)->byte_offset;
          auto it = m_value_reg_offset_map.find(reg.kinds[eRegisterKindLLDB]);
          if (it != m_value_reg_offset_map.end())
            reg.byte_offset += it->second;
        }
      }
    }

    reg_offset = reg.byte_offset + reg.byte_size;
    if (m_reg_data_byte_size < reg_offset)
      m_reg_data_byte_size = reg_offset;
  }
}

bool RegisterDescriptionBuilder::IsReconfigurable() {
  return m_is_reconfigurable;
}

size_t RegisterDescriptionBuilder::GetNumRegisters() const {
  return m_regs.size();
}

size_t RegisterDescriptionBuilder::GetNumRegisterSets() const {
  return m_sets.size();
}

size_t RegisterDescriptionBuilder::GetRegisterDataByteSize() const {
  return m_reg_data_byte_size;
}

const RegisterInfo *
RegisterDescriptionBuilder::GetRegisterInfoAtIndex(uint32_t i) const {
  if (i < m_regs.size())
    return &m_regs[i];
  return nullptr;
}

const RegisterInfo *
RegisterDescriptionBuilder::GetRegisterInfo(uint32_t kind, uint32_t num) const {
  uint32_t reg_index = ConvertRegisterKindToRegisterNumber(kind, num);
  if (reg_index != LLDB_INVALID_REGNUM)
    return &m_regs[reg_index];
  return nullptr;
}

const RegisterSet *
RegisterDescriptionBuilder::GetRegisterSet(uint32_t i) const {
  if (i < m_sets.size())
    return &(m_sets[i].m_set);
  return nullptr;
}

uint32_t RegisterDescriptionBuilder::ConvertRegisterKindToRegisterNumber(
    uint32_t kind, uint32_t num) const {
  reg_collection::const_iterator pos, end = m_regs.end();
  for (pos = m_regs.begin(); pos != end; ++pos) {
    if (pos->kinds[kind] == num)
      return std::distance(m_regs.begin(), pos);
  }

  return LLDB_INVALID_REGNUM;
}

void RegisterDescriptionBuilder::Clear() {
  m_regs.clear();
  m_architecture_ids.clear();
  m_sets.clear();
  m_set_reg_nums.clear();
  m_value_regs_map.clear();
  m_invalidate_regs_map.clear();
  m_value_reg_offset_map.clear();
  m_is_reconfigurable = false;
  m_reg_data_byte_size = 0;
  m_finalized = false;
}

const lldb_private::RegisterInfo *
RegisterDescriptionBuilder::GetRegisterInfo(llvm::StringRef reg_name) const {
  for (auto &reg_info : m_regs)
    if (reg_info.name == reg_name)
      return &reg_info;
  return nullptr;
}

void lldb_private::addSupplementaryRegister(
    std::vector<RegisterDescriptionBuilder::Register> &regs,
    RegisterDescriptionBuilder::Register new_reg_info) {
  assert(!new_reg_info.value_regs.empty());
  const uint32_t reg_num = regs.size();
  regs.push_back(new_reg_info);

  std::map<uint32_t, std::vector<uint32_t>> new_invalidates;
  for (uint32_t value_reg : new_reg_info.value_regs) {
    // copy value_regs to invalidate_regs
    new_invalidates[reg_num].push_back(value_reg);

    // copy invalidate_regs from the parent register
    llvm::append_range(new_invalidates[reg_num],
                       regs[value_reg].invalidate_regs);

    // add reverse invalidate entries
    for (uint32_t x : new_invalidates[reg_num])
      new_invalidates[x].push_back(reg_num);
  }

  for (const auto &x : new_invalidates)
    llvm::append_range(regs[x.first].invalidate_regs, x.second);
}

llvm::Expected<RegisterDescriptionBuilder::Model>
RegisterDescriptionBuilder::BuildModel(lldb::ByteOrder byte_order) const {
  if (!m_finalized)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "register description is not finalized");
  std::vector<RegisterSet> groups;
  for (const auto &set : m_sets)
    groups.push_back(set.m_set);
  auto description = RegisterDescription::FromLegacy(m_regs, groups);
  if (!description)
    return description.takeError();
  // A source table position is a presentation index, never an architecture ID.
  std::vector<RegisterDescriptor> regs(description->GetRegisters().begin(),
                                       description->GetRegisters().end());
  std::vector<RegisterGroup> logical_groups(description->GetGroups().begin(),
                                            description->GetGroups().end());
  std::map<RegisterID, RegisterID> ids;
  for (size_t i = 0; i < regs.size(); ++i)
    ids[regs[i].id] = i < m_architecture_ids.size() &&
                              m_architecture_ids[i] != LLDB_INVALID_REGNUM
                          ? m_architecture_ids[i]
                          : regs[i].id;
  for (auto &reg : regs) {
    reg.id = ids.at(reg.id);
    for (auto *refs : {&reg.value_registers, &reg.invalidate_registers})
      for (auto &id : *refs)
        id = ids.at(id);
  }
  for (auto &group : logical_groups)
    for (auto &id : group.registers)
      id = ids.at(id);
  auto normalized =
      RegisterDescription::Create(std::move(regs), std::move(logical_groups));
  if (!normalized)
    return normalized.takeError();
  auto owned = std::make_shared<RegisterDescription>(std::move(*normalized));
  auto layout = RegisterLayout::FromLegacy(*owned, m_regs, m_reg_data_byte_size,
                                           byte_order);
  if (!layout)
    return layout.takeError();
  return Model{std::move(owned), std::move(*layout)};
}
