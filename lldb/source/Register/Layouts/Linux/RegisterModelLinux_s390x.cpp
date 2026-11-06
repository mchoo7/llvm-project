//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/Linux/RegisterModelLinux_s390x.h"
#include "lldb/Register/Arch/lldb-s390x-register-enums.h"
using namespace lldb_private;
namespace {
std::shared_ptr<const RegisterDescription> LinuxDescription() {
  static const auto result = [] {
    auto cpu = RegisterInfo_s390x::CreateDescription();
    std::vector<RegisterDescriptor> regs(cpu->GetRegisters().begin(),
                                         cpu->GetRegisters().end());
    std::vector<RegisterGroup> groups(cpu->GetGroups().begin(),
                                      cpu->GetGroups().end());
    RegisterGroup linux_group{"Linux Operating System Data", "linux", {}};
    for (auto entry : {std::pair<const char *, uint32_t>{"orig_r2", 8},
                       {"last_break", 8},
                       {"system_call", 4}}) {
      RegisterDescriptor reg;
      reg.id = lldb_orig_r2_s390x + linux_group.registers.size();
      reg.name = entry.first;
      reg.byte_size = entry.second;
      reg.encoding = lldb::eEncodingUint;
      reg.format = lldb::eFormatHex;
      reg.numbers.fill(LLDB_INVALID_REGNUM);
      reg.numbers[lldb::eRegisterKindLLDB] = reg.id;
      linux_group.registers.push_back(reg.id);
      regs.push_back(std::move(reg));
    }
    groups.push_back(std::move(linux_group));
    return std::make_shared<RegisterDescription>(llvm::cantFail(
        RegisterDescription::Create(std::move(regs), std::move(groups))));
  }();
  return result;
}
RegisterLayout Layout(const ArchSpec &arch) {
  RegisterLayout layout(arch.GetByteOrder());
  // Linux user_regs_struct, user_fpregs_struct, LAST_BREAK and SYSTEM_CALL
  // notes.
  llvm::cantFail(layout.AddBank(0, 216));
  llvm::cantFail(layout.AddBank(1, 136));
  llvm::cantFail(layout.AddBank(2, 8));
  llvm::cantFail(layout.AddBank(3, 4));
  auto add = [&](RegisterID id, RegisterBankID bank, uint32_t offset,
                 uint32_t size) {
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({bank, offset, size});

    llvm::cantFail(layout.Add(id, std::move(location)));
  };
  for (uint32_t i = 0; i < 16; ++i) {
    add(lldb_r0_s390x + i, 0, 16 + 8 * i, 8);
    add(lldb_acr0_s390x + i, 0, 144 + 4 * i, 4);
    add(lldb_f0_s390x + i, 1, 8 + 8 * i, 8);
  }
  add(lldb_pswm_s390x, 0, 0, 8);
  add(lldb_pswa_s390x, 0, 8, 8);
  add(lldb_fpc_s390x, 1, 0, 4);
  add(lldb_orig_r2_s390x, 0, 208, 8);
  add(lldb_last_break_s390x, 2, 0, 8);
  add(lldb_system_call_s390x, 3, 0, 4);
  llvm::cantFail(layout.Validate(*LinuxDescription()));
  return layout;
}
} // namespace
RegisterModel
lldb_private::CreateLinuxS390XRegisterModel(const ArchSpec &arch) {
  return {LinuxDescription(), Layout(arch)};
}
