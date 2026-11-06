//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Plugins/Process/gdb-remote/RegisterPacketLayout.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
using namespace lldb_private;
using namespace lldb_private::process_gdb_remote;
using namespace llvm;
namespace {
RegisterInfo Register(const char *name, uint32_t number, uint32_t size,
                      uint32_t native_offset) {
  RegisterInfo result{};
  result.name = name;
  result.byte_size = size;
  result.byte_offset = native_offset;
  std::fill(std::begin(result.kinds), std::end(result.kinds),
            LLDB_INVALID_REGNUM);
  result.kinds[lldb::eRegisterKindLLDB] = number;
  return result;
}
} // namespace
TEST(RegisterPacketLayoutTest, IgnoresNativeOffsetsAndResolvesForwardAliases) {
  uint32_t parent[] = {90, LLDB_INVALID_REGNUM};
  uint32_t invalidates[] = {20, 90, LLDB_INVALID_REGNUM};
  RegisterInfo regs[] = {Register("high", 20, 1, 999), Register("pc", 42, 8, 0),
                         Register("full", 90, 8, 0)};
  regs[0].value_regs = parent;
  regs[2].invalidate_regs = invalidates;
  auto packet = RegisterPacketLayout::Create(regs, {1, 0, 0});
  ASSERT_THAT_EXPECTED(packet, Succeeded());
  EXPECT_EQ(packet->GetByteSize(), 16u);
  EXPECT_FALSE(packet->IsPrimary(0));
  EXPECT_EQ(packet->GetRegisters()[0].byte_offset, 9u);
  EXPECT_EQ(packet->GetRegisters()[1].byte_offset, 0u);
  EXPECT_EQ(packet->GetRegisters()[2].byte_offset, 8u);
  EXPECT_EQ(packet->GetRegisters()[0].value_regs[0], 2u);
  EXPECT_EQ(packet->GetRegisters()[2].invalidate_regs[0], 0u);
  auto moved = std::move(*packet);
  EXPECT_EQ(moved.GetRegisters()[0].value_regs[0], 2u);
}
TEST(RegisterPacketLayoutTest, RejectsCyclesAndOutOfBoundsAliases) {
  uint32_t first[] = {5, LLDB_INVALID_REGNUM};
  uint32_t second[] = {9, LLDB_INVALID_REGNUM};
  RegisterInfo regs[] = {Register("a", 9, 8, 0), Register("b", 5, 8, 0)};
  regs[0].value_regs = first;
  regs[1].value_regs = second;
  EXPECT_THAT_EXPECTED(RegisterPacketLayout::Create(regs, {0, 0}), Failed());
  regs[1].value_regs = nullptr;
  EXPECT_THAT_EXPECTED(RegisterPacketLayout::Create(regs, {1, 0}), Failed());
  EXPECT_THAT_EXPECTED(RegisterPacketLayout::Create(regs, {0}), Failed());
}
TEST(RegisterPacketLayoutTest,
     InvisibleParentsAndCompositesHaveOwnPacketSlots) {
  uint32_t absent[] = {99, LLDB_INVALID_REGNUM};
  uint32_t pieces[] = {10, 20, LLDB_INVALID_REGNUM};
  RegisterInfo regs[] = {Register("a", 10, 4, 0), Register("b", 20, 4, 0),
                         Register("both", 30, 8, 0)};
  regs[0].value_regs = absent;
  regs[2].value_regs = pieces;
  auto packet = RegisterPacketLayout::Create(regs, {0, 0, 0});
  ASSERT_THAT_EXPECTED(packet, Succeeded());
  EXPECT_TRUE(packet->IsPrimary(0));
  EXPECT_TRUE(packet->IsPrimary(2));
  EXPECT_EQ(packet->GetRegisters()[2].byte_offset, 8u);
  EXPECT_EQ(packet->GetByteSize(), 16u);
}
