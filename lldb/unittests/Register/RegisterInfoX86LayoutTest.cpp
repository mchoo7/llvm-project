//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/FreeBSD/RegisterModelFreeBSD_x86_64.h"
#include "gtest/gtest.h"
using namespace lldb_private;

TEST(RegisterInfoX86LayoutTest, Compat32LayoutOwnsNamesFromTemporaryProvider) {
  RegisterInfo_x86 provider(
      ArchSpec("i386-unknown-freebsd"),
      CreateFreeBSDX86_64RegisterModel(ArchSpec("i386-unknown-freebsd")));
  EXPECT_EQ(provider.GetGPRSize(), 176u);
  EXPECT_STREQ(provider.GetRegisterInfo()[lldb_eax_i386].name, "eax");
  EXPECT_EQ(provider.GetRegisterInfo()[lldb_eax_i386].byte_size, 4u);
  EXPECT_EQ(provider.GetLayout()
                .Find(provider.GetDescription().Find("eax")->id)
                ->pieces[0]
                .byte_offset,
            14 * 8u);
  EXPECT_EQ(provider.GetDescription().Find("eax")->byte_size, 4u);
}
