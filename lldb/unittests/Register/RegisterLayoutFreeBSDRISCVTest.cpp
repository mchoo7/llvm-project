//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Arch/lldb-riscv-register-enums.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_riscv64.h"
#include "lldb/Utility/ArchSpec.h"
#include "llvm/Support/Endian.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <array>
#include <iterator>

namespace reg_ids = lldb_private::registers::riscv::id;
using namespace lldb_private;
using namespace llvm;

TEST(RegisterLayoutFreeBSDRISCVTest, KernelRegisterOrder) {
  auto layout =
      CreateFreeBSDRISCV64RegisterLayout(ArchSpec("riscv64-unknown-freebsd"), false);
  // Slots in struct reg are ABI order, not architectural register order.
  const RegisterID slots[] = {
      reg_ids::gpr_ra, reg_ids::gpr_sp,  reg_ids::gpr_gp,  reg_ids::gpr_tp,
      reg_ids::gpr_t0, reg_ids::gpr_t1,  reg_ids::gpr_t2,  reg_ids::gpr_t3,
      reg_ids::gpr_t4, reg_ids::gpr_t5,  reg_ids::gpr_t6,  reg_ids::gpr_fp,
      reg_ids::gpr_s1, reg_ids::gpr_s2,  reg_ids::gpr_s3,  reg_ids::gpr_s4,
      reg_ids::gpr_s5, reg_ids::gpr_s6,  reg_ids::gpr_s7,  reg_ids::gpr_s8,
      reg_ids::gpr_s9, reg_ids::gpr_s10, reg_ids::gpr_s11, reg_ids::gpr_a0,
      reg_ids::gpr_a1, reg_ids::gpr_a2,  reg_ids::gpr_a3,  reg_ids::gpr_a4,
      reg_ids::gpr_a5, reg_ids::gpr_a6,  reg_ids::gpr_a7,  reg_ids::gpr_pc};
  std::array<uint8_t, sizeof(freebsd_riscv64::GPR)> bytes{};
  for (size_t i = 0; i != std::size(slots); ++i)
    support::endian::write64le(bytes.data() + i * 8, 0x100 + i);
  RegisterData data{0, bytes};
  for (size_t i = 0; i != std::size(slots); ++i) {
    auto value = layout.Read(slots[i], data);
    ASSERT_THAT_EXPECTED(value, Succeeded());
    EXPECT_EQ(value->GetAsUInt64(), 0x100u + i);
  }
  auto zero = layout.Read(reg_ids::gpr_x0, {});
  ASSERT_THAT_EXPECTED(zero, Succeeded());
  EXPECT_EQ(zero->GetAsUInt64(), 0u);
  EXPECT_EQ(layout.GetBankSize(0), 264u);
  EXPECT_EQ(layout.GetBankSize(1), 0u);
  EXPECT_EQ(layout.GetDescription()->Find(reg_ids::fpr_f0), nullptr);
}

TEST(RegisterLayoutFreeBSDRISCVTest, FloatingPointSlotsPreserveUnusedBytes) {
  auto layout =
      CreateFreeBSDRISCV64RegisterLayout(ArchSpec("riscv64-unknown-freebsd"), true);
  EXPECT_EQ(layout.GetBankSize(1), 520u);
  std::array<uint8_t, sizeof(freebsd_riscv64::FPR)> bytes;
  bytes.fill(0xa5);
  MutableRegisterData writable{1, bytes};
  RegisterData readable{1, bytes};
  RegisterValue value(uint64_t(0x0123456789abcdef));
  for (RegisterID i = 0; i != 32; ++i) {
    ASSERT_THAT_ERROR(layout.Write(reg_ids::fpr_f0 + i, value, writable),
                      Succeeded());
    EXPECT_EQ(support::endian::read64le(bytes.data() + i * 16),
              0x0123456789abcdefULL);
    EXPECT_EQ(support::endian::read64le(bytes.data() + i * 16 + 8),
              0xa5a5a5a5a5a5a5a5ULL);
    auto read = layout.Read(reg_ids::fpr_f0 + i, readable);
    ASSERT_THAT_EXPECTED(read, Succeeded());
    EXPECT_EQ(read->GetAsUInt64(), value.GetAsUInt64());
  }
  ASSERT_THAT_ERROR(
      layout.Write(reg_ids::fpr_fcsr, RegisterValue(uint32_t(7)), writable),
      Succeeded());
  EXPECT_EQ(support::endian::read32le(bytes.data() + 512), 7u);
  EXPECT_EQ(support::endian::read32le(bytes.data() + 516), 0xa5a5a5a5u);
  EXPECT_THAT_ERROR(layout.Write(reg_ids::gpr_x0, RegisterValue(uint64_t(1)), {}),
                    Failed());
}
