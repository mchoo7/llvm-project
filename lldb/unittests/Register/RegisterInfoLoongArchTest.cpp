//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Arch/lldb-loongarch-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_loongarch64.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_loongarch64.h"
#include "lldb/Register/RegisterCodec.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <array>
using namespace lldb_private;
using namespace llvm;

TEST(RegisterInfoLoongArchTest, LinuxStateIsAnExplicitExtension) {
  auto cpu = RegisterInfo_loongarch64::CreateDescription();
  EXPECT_EQ(cpu->Find("orig_a0"), nullptr);
  EXPECT_EQ(cpu->Find("reserved0"), nullptr);
  ASSERT_NE(cpu->Find(gpr_pc_loongarch), nullptr);
  auto model = CreateLinuxLoongArch64RegisterModel(
      ArchSpec("loongarch64-unknown-linux"));
  auto linux_description = model.description;
  EXPECT_NE(linux_description->Find("orig_a0"), nullptr);
  EXPECT_NE(linux_description->Find("reserved9"), nullptr);
  RegisterInfo_loongarch64 linux_provider(ArchSpec("loongarch64-unknown-linux"),
                                          std::move(model));
  EXPECT_EQ(linux_provider.GetGPRSize(), 360u);
  EXPECT_EQ(linux_provider.GetFPRSize(), 272u);
  EXPECT_STREQ(linux_provider.GetRegisterInfo()[gpr_pc_loongarch].name, "pc");
  EXPECT_EQ(
      linux_provider.GetLayout().Find(gpr_pc_loongarch)->pieces[0].byte_offset,
      264u);

  RegisterInfo_loongarch64 other(ArchSpec("loongarch64-unknown-freebsd"), cpu,
                                 RegisterLayout(lldb::eByteOrderLittle));
  EXPECT_EQ(other.GetRegisterInfo()[32].kinds[lldb::eRegisterKindLLDB],
            gpr_pc_loongarch);
  EXPECT_EQ(other.GetRegisterSetFromRegisterNumber(fpr_fcsr_loongarch),
            RegisterInfo_loongarch64::FPRegSet);
}

TEST(RegisterInfoLoongArchTest,
     ArchitectureDescriptionAcceptsAnotherBankLayout) {
  auto description = RegisterInfo_loongarch64::CreateDescription();
  RegisterLayout layout(lldb::eByteOrderBig);
  ASSERT_THAT_ERROR(layout.AddBank(9, 8), Succeeded());
  RegisterLocation pc;
  pc.kind = RegisterLocation::Stored;
  pc.pieces = {{9, 0, 8, 0}};
  ASSERT_THAT_ERROR(layout.Add(gpr_pc_loongarch, pc), Succeeded());
  std::array<uint8_t, 8> bytes{1, 2, 3, 4, 5, 6, 7, 8};
  RegisterData bank{9, bytes};
  auto value =
      RegisterCodec::Read(*description, layout, gpr_pc_loongarch, bank);
  ASSERT_THAT_EXPECTED(value, Succeeded());
  EXPECT_EQ(value->GetAsUInt64(), 0x0102030405060708ULL);
}
