//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/RegisterDescriptionBuilder.h"
#include "gtest/gtest.h"
using namespace lldb_private;
TEST(RegisterDescriptionBuilderTest,
     ExportsOwnedMetadataAndExplicitPacketLayout) {
  RegisterDescriptionBuilder builder;
  RegisterDescriptionBuilder::Register reg;
  reg.name = ConstString("value");
  reg.set_name = ConstString("gpr");
  reg.byte_size = 8;
  reg.byte_offset = 24;
  reg.regnum_remote = 7;
  reg.regnum_dwarf = 19;
  builder.SetRegisterInfo({reg}, ArchSpec("riscv64-unknown-unknown"));
  auto model = builder.BuildModel(lldb::eByteOrderBig);
  ASSERT_TRUE(bool(model));
  builder.Clear();
  const auto *value = model->description->Find("value");
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(value->numbers[lldb::eRegisterKindDWARF], 19u);
  EXPECT_EQ(model->layout.Find(value->id)->pieces[0].byte_offset, 24u);
  EXPECT_EQ(model->layout.GetByteOrder(), lldb::eByteOrderBig);
  EXPECT_EQ(model->description->GetGroups()[0].registers[0], value->id);
}
TEST(RegisterDescriptionBuilderTest, RefusesUnfinalizedModel) {
  RegisterDescriptionBuilder builder;
  auto model = builder.BuildModel(lldb::eByteOrderLittle);
  ASSERT_FALSE(bool(model));
  llvm::consumeError(model.takeError());
}

TEST(RegisterDescriptionBuilderTest, IdentitySurvivesSparsePresentation) {
  RegisterDescriptionBuilder builder;
  RegisterDescriptionBuilder::Register value;
  value.name = ConstString("value");
  value.set_name = ConstString("gpr");
  value.byte_size = 4;
  value.byte_offset = 0;
  value.regnum_remote = 0;
  value.id = 101;
  builder.SetRegisterInfo({value}, ArchSpec("riscv32-unknown-unknown"));
  auto model = builder.BuildModel(lldb::eByteOrderBig);
  ASSERT_TRUE(bool(model));
  const auto *reg = model->description->Find(101);
  ASSERT_NE(reg, nullptr);
  EXPECT_EQ(reg->numbers[lldb::eRegisterKindLLDB], 0u);
  EXPECT_EQ(model->description->GetGroups()[0].registers[0], 101u);
  ASSERT_NE(model->layout.Find(101), nullptr);
}

TEST(RegisterDescriptionBuilderTest, CopyOwnsRelationshipsAndGroups) {
  RegisterDescriptionBuilder original;
  RegisterDescriptionBuilder::Register parent;
  parent.name = ConstString("parent");
  parent.set_name = ConstString("gpr");
  parent.byte_size = 8;
  parent.byte_offset = 0;
  parent.regnum_remote = 0;
  auto alias = parent;
  alias.name = ConstString("alias");
  alias.byte_size = 4;
  alias.regnum_remote = 1;
  alias.value_regs = {0};
  alias.invalidate_regs = {0};
  original.SetRegisterInfo({parent, alias}, ArchSpec("x86_64-unknown-unknown"));
  RegisterDescriptionBuilder copy(original);
  original.Clear();
  EXPECT_EQ(copy.GetRegisterInfoAtIndex(1)->value_regs[0], 0u);
  EXPECT_EQ(copy.GetRegisterInfoAtIndex(1)->invalidate_regs[0], 0u);
  EXPECT_STREQ(copy.GetRegisterSet(0)->name, "gpr");
  EXPECT_EQ(copy.GetRegisterSet(0)->registers[1], 1u);
  auto model = copy.BuildModel(lldb::eByteOrderLittle);
  ASSERT_TRUE(bool(model));
}
