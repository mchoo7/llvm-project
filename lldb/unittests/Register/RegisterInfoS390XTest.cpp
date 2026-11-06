//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_s390x.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_s390x.h"
#include "gtest/gtest.h"
using namespace lldb_private;
TEST(RegisterInfoS390XTest, LinuxStateIsAnExplicitExtension) {
  auto cpu = RegisterInfo_s390x::CreateDescription();
  EXPECT_EQ(cpu->Find("orig_r2"), nullptr);
  EXPECT_EQ(cpu->Find("last_break"), nullptr);
  RegisterInfo_s390x linux_info(
      ArchSpec("s390x-unknown-linux"),
      CreateLinuxS390XRegisterModel(ArchSpec("s390x-unknown-linux")));
  auto *orig = linux_info.GetDescription().Find("orig_r2");
  ASSERT_NE(orig, nullptr);
  EXPECT_EQ(linux_info.GetLayout().Find(orig->id)->pieces[0].byte_offset, 208u);
  auto *f0 = cpu->Find("f0");
  ASSERT_NE(f0, nullptr);
  EXPECT_EQ(linux_info.GetLayout().Find(f0->id)->pieces[0].bank, 1u);
  EXPECT_EQ(linux_info.GetLayout().Find(f0->id)->pieces[0].byte_offset, 8u);
  EXPECT_EQ(linux_info.GetRegisterInfoByNumber(f0->id)->byte_offset, 0u);
}
