//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_REGISTERDESCRIPTIONBUILDER_H
#define LLDB_REGISTER_REGISTERDESCRIPTIONBUILDER_H

#include <map>
#include <vector>

#include "lldb/Register/RegisterLayout.h"
#include "lldb/Utility/ArchSpec.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/RegisterInfo.h"
#include "lldb/Utility/RegisterTypeFlags.h"
#include "lldb/lldb-private.h"

namespace lldb_private {
class Stream;

class RegisterDescriptionBuilder {
public:
  struct Register {
    ConstString name;
    ConstString alt_name;
    ConstString set_name;
    uint32_t byte_size = LLDB_INVALID_INDEX32;
    uint32_t byte_offset = LLDB_INVALID_INDEX32;
    lldb::Encoding encoding = lldb::eEncodingUint;
    lldb::Format format = lldb::eFormatHex;
    uint32_t regnum_dwarf = LLDB_INVALID_REGNUM;
    uint32_t regnum_ehframe = LLDB_INVALID_REGNUM;
    uint32_t regnum_generic = LLDB_INVALID_REGNUM;
    uint32_t regnum_remote = LLDB_INVALID_REGNUM;
    std::vector<uint32_t> value_regs;
    std::vector<uint32_t> invalidate_regs;
    uint32_t value_reg_offset = 0;
    // Non-null if there is an XML provided type.
    const RegisterType *register_type = nullptr;
    RegisterID id = LLDB_INVALID_REGNUM;
  };

  RegisterDescriptionBuilder() = default;
  RegisterDescriptionBuilder(const RegisterDescriptionBuilder &info);
  RegisterDescriptionBuilder &operator=(const RegisterDescriptionBuilder &info);

  virtual ~RegisterDescriptionBuilder() = default;

  RegisterDescriptionBuilder(RegisterDescriptionBuilder &&info);
  RegisterDescriptionBuilder &operator=(RegisterDescriptionBuilder &&info);

  size_t SetRegisterInfo(std::vector<Register> &&regs,
                         const lldb_private::ArchSpec &arch);

  size_t GetNumRegisters() const;

  size_t GetNumRegisterSets() const;

  size_t GetRegisterDataByteSize() const;

  const lldb_private::RegisterInfo *GetRegisterInfoAtIndex(uint32_t i) const;

  const lldb_private::RegisterSet *GetRegisterSet(uint32_t i) const;

  uint32_t ConvertRegisterKindToRegisterNumber(uint32_t kind,
                                               uint32_t num) const;

  const lldb_private::RegisterInfo *GetRegisterInfo(uint32_t kind,
                                                    uint32_t num) const;

  void Clear();

  bool IsReconfigurable();

  const lldb_private::RegisterInfo *
  GetRegisterInfo(llvm::StringRef reg_name) const;

  typedef std::vector<lldb_private::RegisterInfo> reg_collection;
  typedef llvm::iterator_range<reg_collection::const_iterator>
      reg_collection_const_range;
  typedef llvm::iterator_range<reg_collection::iterator> reg_collection_range;

  template <typename T> T registers() = delete;

  template <typename T> T registers() const = delete;

  void ConfigureOffsets();

  using Model = RegisterModel;
  /// Export the current finalized values through the common description/layout
  /// model. Parsing policies and error presentation belong to the caller.
  llvm::Expected<Model> BuildModel(lldb::ByteOrder byte_order) const;

protected:
  struct RegisterSetWithStorage {
    RegisterSetWithStorage(std::string name, std::string short_name,
                           size_t num_registers, const uint32_t *registers)
        : m_name(std::move(name)), m_short_name(std::move(short_name)) {
      m_set.name = m_name.c_str();
      m_set.short_name = m_short_name.c_str();
      m_set.num_registers = num_registers;
      m_set.registers = registers;
    }

    RegisterSetWithStorage(const RegisterSetWithStorage &rhs)
        : m_name(rhs.m_name), m_short_name(rhs.m_short_name) {
      m_set = rhs.m_set;
      // m_set's strings must be re-set, otherwise they will still point to
      // strings in rhs.
      m_set.name = m_name.c_str();
      m_set.short_name = m_short_name.c_str();
    }

    RegisterSetWithStorage(RegisterSetWithStorage &&rhs)
        : m_set(rhs.m_set), m_name(std::move(rhs.m_name)),
          m_short_name(std::move(rhs.m_short_name)) {
      // m_set's strings must be re-set, otherwise they will still point to
      // strings in rhs.
      m_set.name = m_name.c_str();
      m_set.short_name = m_short_name.c_str();
    }

    lldb_private::RegisterSet m_set;
    std::string m_name;
    std::string m_short_name;
  };

  // Classes that inherit from RegisterDescriptionBuilder can see and modify
  // these
  typedef std::vector<RegisterSetWithStorage> set_collection;
  typedef std::vector<uint32_t> reg_num_collection;
  typedef std::vector<reg_num_collection> set_reg_num_collection;
  typedef std::map<uint32_t, reg_num_collection> reg_to_regs_map;
  typedef std::map<uint32_t, uint32_t> reg_offset_map;

  void MoveFrom(RegisterDescriptionBuilder &&info);

  void Finalize(const lldb_private::ArchSpec &arch);

  reg_collection m_regs;
  std::vector<RegisterID> m_architecture_ids;
  set_collection m_sets;
  set_reg_num_collection m_set_reg_nums;
  reg_to_regs_map m_value_regs_map;
  reg_to_regs_map m_invalidate_regs_map;
  reg_offset_map m_value_reg_offset_map;
  size_t m_reg_data_byte_size = 0u; // The number of bytes required to store
                                    // all registers
  bool m_finalized = false;
  bool m_is_reconfigurable = false;
};

template <>
inline RegisterDescriptionBuilder::reg_collection_const_range
RegisterDescriptionBuilder::registers() {
  return reg_collection_const_range(m_regs);
}

template <>
inline RegisterDescriptionBuilder::reg_collection_range
RegisterDescriptionBuilder::registers() {
  return reg_collection_range(m_regs);
}

template <>
inline RegisterDescriptionBuilder::reg_collection_const_range
RegisterDescriptionBuilder::registers() const {
  return reg_collection_const_range(m_regs);
}

void addSupplementaryRegister(
    std::vector<RegisterDescriptionBuilder::Register> &regs,
    RegisterDescriptionBuilder::Register new_reg_info);

} // namespace lldb_private

#endif // LLDB_REGISTER_REGISTERDESCRIPTIONBUILDER_H
