//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_riscv64.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_riscv64.h"
#include "lldb/Register/RegisterCodec.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <array>

using namespace lldb_private;
using namespace llvm;

TEST(RegisterInfoRISCVTest, OneDescriptionSupportsDifferentStorage) {
  auto description = RegisterInfo_riscv64::CreateDescription(0);
  auto linux_layout =
      CreateLinuxRISCV64RegisterModel(ArchSpec("riscv64-unknown-linux"), 0)
          .layout;
  RegisterLayout other(lldb::eByteOrderBig);
  ASSERT_THAT_ERROR(other.AddBank(10, 24), Succeeded());
  RegisterLocation pc;
  pc.kind = RegisterLocation::Stored;
  pc.pieces = {{10, 16, 8, 0}};
  ASSERT_THAT_ERROR(other.Add(gpr_pc_riscv, pc), Succeeded());
  std::array<uint8_t, 256> linux_bytes{};
  std::array<uint8_t, 24> other_bytes{};
  MutableRegisterData linux_data{0, linux_bytes}, other_data{10, other_bytes};
  RegisterValue value(uint64_t(0x0102030405060708));
  ASSERT_THAT_ERROR(RegisterCodec::Write(*description, linux_layout,
                                         gpr_pc_riscv, value, linux_data),
                    Succeeded());
  ASSERT_THAT_ERROR(RegisterCodec::Write(*description, other, gpr_pc_riscv,
                                         value, other_data),
                    Succeeded());
  EXPECT_EQ(linux_bytes[0], 8);
  EXPECT_EQ(other_bytes[16], 1);
  RegisterData linux_read{0, linux_bytes}, other_read{10, other_bytes};
  auto a =
      RegisterCodec::Read(*description, linux_layout, gpr_pc_riscv, linux_read);
  auto b = RegisterCodec::Read(*description, other, gpr_pc_riscv, other_read);
  ASSERT_THAT_EXPECTED(a, Succeeded());
  ASSERT_THAT_EXPECTED(b, Succeeded());
  EXPECT_EQ(a->GetAsUInt64(), b->GetAsUInt64());
  auto zero = RegisterCodec::Read(*description, linux_layout, gpr_x0_riscv, {});
  ASSERT_THAT_EXPECTED(zero, Succeeded());
  EXPECT_EQ(zero->GetAsUInt64(), 0u);
}

TEST(RegisterInfoRISCVTest, FloatingPointAndConstantLocations) {
  Flags flags(RegisterInfo_riscv64::eRegsetMaskFP);
  auto model = CreateLinuxRISCV64RegisterModel(
      ArchSpec("riscv64-unknown-linux"), flags);
  auto description = model.description;
  const auto &layout = model.layout;
  RegisterInfo_riscv64 provider(ArchSpec("riscv64-unknown-linux"), flags, model);
  EXPECT_EQ(&provider.GetDescription(), description.get());
  EXPECT_TRUE(provider.IsFPPresent());
  EXPECT_EQ(provider.GetGPRSize(), 256u);
  EXPECT_EQ(provider.GetFPRSize(), 264u);
  EXPECT_EQ(layout.Find(fpr_fcsr_riscv)->pieces[0].bank, 1u);
  EXPECT_EQ(layout.Find(fpr_fcsr_riscv)->pieces[0].byte_offset, 256u);
  EXPECT_EQ(layout.Find(gpr_x0_riscv)->kind, RegisterLocation::Constant);
  EXPECT_EQ(provider.GetRegisterSetFromRegisterIndex(fpr_fcsr_riscv), 1u);
  // Padding after fcsr is not needed to decode its value.
  std::array<uint8_t, 260> fp{};
  fp[256] = 5;
  RegisterData bank{1, fp};
  auto fcsr = RegisterCodec::Read(*description, layout, fpr_fcsr_riscv, bank);
  ASSERT_THAT_EXPECTED(fcsr, Succeeded());
  EXPECT_EQ(fcsr->GetAsUInt32(), 5u);
}
