//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Plugins/Process/FreeBSD-Kernel-Core/RegisterContextFreeBSDKernelCore_powerpc.h"
#include "llvm/Support/Endian.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <array>

using namespace lldb_private;
using namespace llvm;

TEST(RegisterLayoutFreeBSDKernelCorePowerPCTest,
     PPC64PCBIsReadInTargetByteOrder) {
  for (bool big : {false, true}) {
    constexpr uint64_t thread_address = 0xc012345678abcdefULL;
    auto layout = freebsd_kernel::CreatePowerPCRegisterLayout(
        ArchSpec(big ? "powerpc64-unknown-freebsd"
                     : "powerpc64le-unknown-freebsd"),
        thread_address);
    auto description = layout.GetDescription();
    std::array<uint8_t, 24 * 8> pcb{};
    for (unsigned i = 0; i != 24; ++i) {
      uint64_t value = 0x1234567800000000ULL + i;
      if (big)
        support::endian::write64be(pcb.data() + i * 8, value);
      else
        support::endian::write64le(pcb.data() + i * 8, value);
    }
    RegisterData data{0, pcb};
    auto check = [&](const std::string &name, unsigned slot) {
      const auto *reg = description->Find(name);
      ASSERT_NE(reg, nullptr);
      auto value = layout.Read(reg->id, data);
      ASSERT_THAT_EXPECTED(value, Succeeded());
      EXPECT_EQ(value->GetAsUInt64(), 0x1234567800000000ULL + slot);
    };
    EXPECT_EQ(layout.GetBankSize(0), pcb.size());
    for (unsigned i = 12; i != 32; ++i)
      if (i != 13)
        check("r" + std::to_string(i), i - 12);
    auto curthread = layout.Read(description->Find("r13")->id, {});
    ASSERT_THAT_EXPECTED(curthread, Succeeded());
    EXPECT_EQ(curthread->GetAsUInt64(), thread_address);
    check("cr", 20);
    check("r1", 21);
    check("r2", 22);
    check("lr", 23);
    check("pc", 23);
    EXPECT_EQ(description->Find("lr")->numbers[lldb::eRegisterKindDWARF], 65u);
    EXPECT_THAT_EXPECTED(layout.Read(description->Find("r0")->id, data),
                         Failed());
    EXPECT_THAT_EXPECTED(layout.Read(description->Find("f0")->id, data),
                         Failed());
    RegisterData short_data{0, ArrayRef<uint8_t>(pcb).drop_back()};
    EXPECT_THAT_EXPECTED(layout.Read(description->Find("pc")->id, short_data),
                         Failed());
  }
}
