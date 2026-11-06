//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Layouts/FreeBSD/RegisterModelFreeBSD_arm.h"
#include "lldb/Register/Common/RegisterInfo_arm.h"
#include "gtest/gtest.h"
using namespace lldb_private;
TEST(RegisterInfoARMTest, MetadataDoesNotRequireSavedState) {
  auto base = RegisterInfo_arm::CreateDescription();
  EXPECT_EQ(base->Find("tpidruro"), nullptr);
  EXPECT_EQ(base->Find("exception"), nullptr);
  EXPECT_EQ(base->Find("bvr0"), nullptr);
  auto extended = RegisterInfo_arm::CreateDescription(true);
  ASSERT_NE(extended->Find("tpidruro"), nullptr);
  EXPECT_EQ(base->Find("pc")->id, extended->Find("pc")->id);
  ArchSpec arch("armv7-unknown-freebsd");
  RegisterInfo_arm saved(arch, CreateFreeBSDArmRegisterModel(arch));
  EXPECT_EQ(saved.GetGPRSize(), 68u);
  auto *fpscr = saved.GetDescription().Find("fpscr");
  ASSERT_NE(fpscr, nullptr);
  EXPECT_EQ(saved.GetLayout().Find(fpscr->id)->pieces[0].byte_offset, 256u);
}
