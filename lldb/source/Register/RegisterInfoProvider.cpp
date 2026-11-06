//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/RegisterInfoProvider.h"
#include "llvm/ADT/STLExtras.h"

using namespace lldb_private;

RegisterInfoProvider::RegisterInfoProvider(
    const ArchSpec &arch,
    std::shared_ptr<const RegisterDescription> description,
    RegisterLayout layout)
    : RegisterInfoAndSetInterface(arch), m_layout(std::move(layout)),
      m_view(llvm::cantFail(
          RegisterInfoView::Create(std::move(description), m_layout))) {}

const RegisterInfo *RegisterInfoProvider::GetRegisterInfo() const {
  return m_view.GetRegisters().data();
}

uint32_t RegisterInfoProvider::GetRegisterCount() const {
  return m_view.GetRegisters().size();
}

const RegisterSet *RegisterInfoProvider::GetRegisterSet(size_t index) const {
  return index < m_view.GetGroups().size() ? &m_view.GetGroups()[index]
                                           : nullptr;
}

size_t RegisterInfoProvider::GetRegisterSetCount() const {
  return m_view.GetGroups().size();
}

size_t
RegisterInfoProvider::GetRegisterSetFromRegisterIndex(uint32_t index) const {
  for (size_t group = 0; group != m_view.GetGroups().size(); ++group) {
    const auto &set = m_view.GetGroups()[group];
    if (llvm::is_contained(llvm::ArrayRef(set.registers, set.num_registers),
                           index))
      return group;
  }
  return LLDB_INVALID_INDEX32;
}

size_t RegisterInfoProvider::GetBankSize(RegisterBankID id) const {
  const auto *bank = m_layout.FindBank(id);
  return bank ? bank->byte_size : 0;
}

size_t
RegisterInfoProvider::GetRegisterSetFromRegisterNumber(uint32_t number) const {
  const auto registers = m_view.GetRegisters();
  for (size_t i = 0; i != registers.size(); ++i)
    if (registers[i].kinds[lldb::eRegisterKindLLDB] == number)
      return GetRegisterSetFromRegisterIndex(i);
  return LLDB_INVALID_INDEX32;
}

const RegisterInfo *
RegisterInfoProvider::GetRegisterInfoByNumber(uint32_t number) const {
  for (const auto &reg : m_view.GetRegisters())
    if (reg.kinds[lldb::eRegisterKindLLDB] == number)
      return &reg;
  return nullptr;
}

void RegisterInfoProvider::Reconfigure(
    std::shared_ptr<const RegisterDescription> description,
    RegisterLayout layout) {
  auto view =
      llvm::cantFail(RegisterInfoView::Create(std::move(description), layout));
  m_layout = std::move(layout);
  m_view.Replace(std::move(view));
}

llvm::Expected<std::vector<RegisterBankID>>
RegisterInfoProvider::GetRegisterBanks(const RegisterInfo &info,
                                       bool writing) const {
  const auto *reg = GetDescription().Find(info.name);
  if (!reg)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "unknown register");
  std::vector<RegisterBankID> banks;
  const auto *location = m_layout.Find(reg->id);
  if (writing && reg->zero_extend_parent != LLDB_INVALID_REGNUM)
    location = m_layout.Find(reg->zero_extend_parent);
  if (!location) {
    if (!reg->constant_value.empty())
      return banks;
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "register has no storage location");
  }
  for (const auto &piece : location->pieces)
    if (!llvm::is_contained(banks, piece.bank))
      banks.push_back(piece.bank);
  return banks;
}
llvm::Expected<RegisterValue> RegisterInfoProvider::ReadRegister(
    const RegisterInfo &info, llvm::ArrayRef<RegisterData> candidates) const {
  const auto *reg = GetDescription().Find(info.name);
  if (!reg)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "unknown register");
  std::vector<RegisterData> banks;
  for (const auto &bank : candidates)
    if (m_layout.FindBank(bank.bank))
      banks.push_back(bank);
  return RegisterCodec::Read(GetDescription(), m_layout, reg->id, banks);
}
llvm::Error RegisterInfoProvider::WriteRegister(
    const RegisterInfo &info, const RegisterValue &value,
    llvm::ArrayRef<MutableRegisterData> candidates) const {
  const auto *reg = GetDescription().Find(info.name);
  if (!reg)
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "unknown register");
  std::vector<MutableRegisterData> banks;
  for (const auto &bank : candidates)
    if (m_layout.FindBank(bank.bank))
      banks.push_back(bank);
  return RegisterCodec::Write(GetDescription(), m_layout, reg->id, value,
                              banks);
}
uint32_t
RegisterInfoProvider::GetRegisterValueOffset(const RegisterInfo &info) const {
  const auto *reg = GetDescription().Find(info.name);
  if (!reg || reg->value_registers.size() != 1)
    return 0;
  const auto *parent = GetDescription().Find(reg->value_registers.front());
  if (GetTargetArchitecture().GetByteOrder() == lldb::eByteOrderBig && parent &&
      reg->byte_size + reg->value_byte_offset <= parent->byte_size)
    return parent->byte_size - reg->byte_size - reg->value_byte_offset;
  return reg->value_byte_offset;
}
