//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Arch/lldb-ppc64le-register-enums.h"
#include "lldb/Register/Common/RegisterInfo_ppc64.h"
#include "lldb/Register/Common/RegisterInfo_ppc64le.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_powerpc.h"
#include "lldb/Register/Layouts/Linux/RegisterLayoutLinux_ppc64le.h"
#include "lldb/Register/RegisterLayout.h"
#include "llvm/Support/Endian.h"
#include "llvm/Testing/Support/Error.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <array>

namespace reg_ids = lldb_private::registers::ppc64le::id;
using namespace lldb_private;
using namespace llvm;

TEST(RegisterInfoPowerPCTest, IdentityDoesNotDependOnEndiannessOrLinuxState) {
  ArchSpec big_arch("powerpc64-unknown-freebsd");
  ArchSpec little_arch("powerpc64le-unknown-freebsd");
  auto big = RegisterInfo_ppc64::CreateDescription(big_arch);
  auto little = RegisterInfo_ppc64le::CreateDescription(little_arch);
  EXPECT_EQ(big->Find("pc")->id, little->Find("pc")->id);
  EXPECT_EQ(big->Find("cr")->id, little->Find("cr")->id);
  EXPECT_EQ(big->Find("vs0")->id, little->Find("vs0")->id);
  for (unsigned i = 0; i != 64; ++i) {
    std::string name = "vs" + std::to_string(i);
    ASSERT_NE(big->Find(name), nullptr);
    ASSERT_NE(little->Find(name), nullptr);
    EXPECT_EQ(big->Find(name)->id, little->Find(name)->id);
  }
  EXPECT_EQ(little->Find("origr3"), nullptr);
  EXPECT_EQ(little->Find("softe"), nullptr);
  EXPECT_EQ(little->Find("trap"), nullptr);
  auto native = std::make_unique<RegisterLayout>(
      CreateLinuxPPC64LERegisterLayout(little_arch));
  EXPECT_NE(native->GetDescription()->Find("origr3"), nullptr);
  EXPECT_NE(native->GetDescription()->Find("trap"), nullptr);
  EXPECT_EQ(native->GetBankSize(0), 352u);
  EXPECT_EQ(native->GetBankSize(1), 264u);
  EXPECT_EQ(native->GetDescription()->GetRegisters()[reg_ids::gpr_pc].name,
            "pc");
  EXPECT_EQ(native->Find(native->GetDescription()->Find("pc")->id)
                ->pieces[0]
                .byte_offset,
            256u);
  EXPECT_EQ(native->GetDescription()->Find("pc")->id, big->Find("pc")->id);
}

TEST(RegisterInfoPowerPCTest, BigEndianDescriptionUsesExplicitStorage) {
  auto description = RegisterInfo_ppc64::CreateDescription(
      ArchSpec("powerpc64-unknown-freebsd"));
  RegisterID pc = description->Find("pc")->id;
  RegisterLayout layout(lldb::eByteOrderBig);
  ASSERT_THAT_ERROR(layout.AddBank(4, 16), Succeeded());
  RegisterLocation saved;
  saved.kind = RegisterLocation::Stored;
  saved.pieces = {{4, 8, 8, 0}};
  ASSERT_THAT_ERROR(layout.Add(pc, saved), Succeeded());
  std::array<uint8_t, 16> bytes{};
  MutableRegisterData bank{4, bytes};
  layout = llvm::cantFail(RegisterLayout::Create(
      std::make_shared<RegisterDescription>(*description), std::move(layout)));

  ASSERT_THAT_ERROR(layout.Write(pc, RegisterValue(uint64_t(0x01020304)), bank),
                    Succeeded());
  EXPECT_EQ(bytes[12], 1);
  EXPECT_EQ(bytes[15], 4);
  RegisterData data{4, bytes};
  auto value = layout.Read(pc, data);
  ASSERT_THAT_EXPECTED(value, Succeeded());
  EXPECT_EQ(value->GetAsUInt64(), 0x01020304u);
}

TEST(RegisterInfoPowerPCTest, FreeBSD32ValuesIn64BitBigEndianSlots) {
  auto compat =
      CreateFreeBSDPowerPC64RegisterLayout(ArchSpec("powerpc-unknown-freebsd"));
  auto *pc = compat.GetDescription()->Find("pc");
  ASSERT_NE(pc, nullptr);
  EXPECT_EQ(pc->byte_size, 4u);
  auto *location = compat.Find(pc->id);
  ASSERT_NE(location, nullptr);
  EXPECT_EQ(compat.GetBankSize(0), 296u);
  EXPECT_EQ(location->pieces[0].byte_offset, 292u);
  EXPECT_EQ(location->pieces[0].byte_size, 4u);
  auto native32 =
      CreateFreeBSDPowerPC32RegisterLayout(ArchSpec("powerpc-unknown-freebsd"));
  EXPECT_EQ(native32.GetBankSize(0), 148u);
  auto *native_pc = native32.GetDescription()->Find("pc");
  EXPECT_EQ(native32.Find(native_pc->id)->pieces[0].byte_offset, 144u);
  auto generic = RegisterInfo_ppc64::CreateDescription(
      ArchSpec("powerpc64-unknown-unknown"));
  EXPECT_EQ(native_pc->id, generic->Find("pc")->id);
}

TEST(RegisterInfoPowerPCTest, LinuxVSXUsesTheActualSplitBanks) {
  auto info = std::make_unique<RegisterLayout>(
      CreateLinuxPPC64LERegisterLayout(ArchSpec("powerpc64le-unknown-linux")));
  const auto *descriptor = info->GetDescription()->Find("vs0");
  const auto *location = info->Find(descriptor->id);
  ASSERT_NE(location, nullptr);
  ASSERT_EQ(location->pieces.size(), 2u);
  EXPECT_EQ(location->pieces[0].bank, 3u);
  EXPECT_EQ(location->pieces[1].bank, 1u);
  std::array<uint8_t, 256> upper{}, floating{};
  upper[0] = 1;
  floating[0] = 2;
  const auto *reg = info->GetDescription()->FindByNumber(
      lldb::eRegisterKindLLDB, descriptor->numbers[lldb::eRegisterKindLLDB]);
  auto value = info->Read(reg->id, {{3, upper}, {1, floating}});
  ASSERT_THAT_EXPECTED(value, Succeeded());
  const auto *bytes = static_cast<const uint8_t *>(value->GetBytes());
  EXPECT_EQ(bytes[0], 1);
  EXPECT_EQ(bytes[8], 2);
}

TEST(RegisterInfoPowerPCTest, FreeBSDPPC64LEUsesNativeWordSlots) {
  auto layout = CreateFreeBSDPowerPC64RegisterLayout(
      ArchSpec("powerpc64le-unknown-freebsd"));
  auto description = layout.GetDescription();
  EXPECT_EQ(layout.GetBankSize(0), 296u);
  EXPECT_EQ(layout.GetBankSize(1), 264u);
  EXPECT_EQ(layout.GetBankSize(2), 528u);
  std::array<uint8_t, 296> bytes{};
  for (unsigned i = 0; i != 32; ++i) {
    auto *reg = description->Find("r" + std::to_string(i));
    ASSERT_NE(reg, nullptr);
    EXPECT_EQ(reg->byte_size, 8u);
    EXPECT_EQ(layout.Find(reg->id)->pieces[0].byte_offset, i * 8u);
    support::endian::write64le(bytes.data() + i * 8, 0x100000000ULL + i);
    auto value = layout.Read(reg->id, RegisterData{0, bytes});
    ASSERT_THAT_EXPECTED(value, Succeeded());
    EXPECT_EQ(value->GetAsUInt64(), 0x100000000ULL + i);
  }
  const char *special[] = {"lr", "cr", "xer", "ctr", "pc"};
  for (unsigned i = 0; i != 5; ++i)
    EXPECT_EQ(
        layout.Find(description->Find(special[i])->id)->pieces[0].byte_offset,
        (32 + i) * 8u);
  EXPECT_EQ(description->Find("lr")->numbers[lldb::eRegisterKindDWARF], 65u);
  EXPECT_EQ(description->Find("cr")->numbers[lldb::eRegisterKindDWARF], 68u);
  EXPECT_EQ(layout.Find(description->Find("vr31")->id)->pieces[0].byte_offset,
            496u);
  EXPECT_EQ(layout.Find(description->Find("vscr")->id)->pieces[0].byte_offset,
            524u);
  EXPECT_EQ(layout.Find(description->Find("vs0")->id), nullptr);
}

TEST(RegisterInfoPowerPCTest, FreeBSDPPC64LEVSXUsesTwoPtraceBanks) {
  auto layout = CreateFreeBSDPowerPC64RegisterLayout(
      ArchSpec("powerpc64le-unknown-freebsd"), true);
  auto description = layout.GetDescription();
  std::array<uint8_t, 264> fp{};
  std::array<uint8_t, 256> extra{};
  std::array<uint8_t, 528> vmx{};
  fp[0] = 0x11;
  extra[0] = 0x22;
  vmx[0] = 0x33;
  auto *vs0 = description->Find("vs0");
  auto value = layout.Read(vs0->id, {{1, fp}, {3, extra}});
  ASSERT_THAT_EXPECTED(value, Succeeded());
  auto *bytes = static_cast<const uint8_t *>(value->GetBytes());
  EXPECT_EQ(bytes[0], 0x22);
  EXPECT_EQ(bytes[8], 0x11);
  auto vs32 = layout.Read(description->Find("vs32")->id, RegisterData{2, vmx});
  ASSERT_THAT_EXPECTED(vs32, Succeeded());
  EXPECT_EQ(static_cast<const uint8_t *>(vs32->GetBytes())[0], 0x33);
  EXPECT_THAT(description->Find("f0")->invalidate_registers,
              ::testing::Contains(vs0->id));
  EXPECT_THAT(description->Find("vr0")->invalidate_registers,
              ::testing::Contains(description->Find("vs32")->id));
  std::array<uint8_t, 16> replacement;
  replacement.fill(0x44);
  RegisterValue written(replacement, lldb::eByteOrderLittle);
  ASSERT_THAT_ERROR(layout.Write(vs0->id, written, {{1, fp}, {3, extra}}),
                    Succeeded());
  EXPECT_EQ(fp[0], 0x44);
  EXPECT_EQ(extra[0], 0x44);
  EXPECT_EQ(fp[8], 0);
  EXPECT_EQ(extra[8], 0);
}

TEST(RegisterInfoPowerPCTest, FreeBSDPPC64UsesELFNumbersAndBigEndianSlots) {
  ArchSpec arch("powerpc64-unknown-freebsd");
  auto layout = CreateFreeBSDPowerPC64RegisterLayout(arch, true);
  auto description = layout.GetDescription();
  const std::pair<const char *, uint32_t> numbers[] = {
      {"lr", 65}, {"ctr", 66}, {"cr", 68}, {"xer", 76}};
  for (const auto &entry : numbers) {
    const auto *reg = description->Find(entry.first);
    ASSERT_NE(reg, nullptr);
    EXPECT_EQ(reg->numbers[lldb::eRegisterKindDWARF], entry.second);
    EXPECT_EQ(reg->numbers[lldb::eRegisterKindEHFrame], entry.second);
  }
  auto aix =
      RegisterInfo_ppc64::CreateDescription(ArchSpec("powerpc64-ibm-aix"));
  EXPECT_EQ(aix->Find("lr")->numbers[lldb::eRegisterKindDWARF], 108u);
  EXPECT_EQ(aix->Find("cr")->numbers[lldb::eRegisterKindDWARF], 64u);
  EXPECT_EQ(description->Find("lr")->id, aix->Find("lr")->id);

  std::array<uint8_t, 296> gp{};
  auto *r31 = description->Find("r31");
  ASSERT_THAT_ERROR(layout.Write(r31->id, RegisterValue(uint64_t(0x123456789)),
                                 MutableRegisterData{0, gp}),
                    Succeeded());
  EXPECT_EQ(support::endian::read64be(gp.data() + 31 * 8), 0x123456789ULL);
  auto read = layout.Read(r31->id, RegisterData{0, gp});
  ASSERT_THAT_EXPECTED(read, Succeeded());
  EXPECT_EQ(read->GetAsUInt64(), 0x123456789ULL);

  std::array<uint8_t, 264> fp{};
  std::array<uint8_t, 256> extra{};
  fp[0] = 0x11;
  extra[0] = 0x22;
  auto *vs0 = description->Find("vs0");
  auto value = layout.Read(vs0->id, {{1, fp}, {3, extra}});
  ASSERT_THAT_EXPECTED(value, Succeeded());
  auto *bytes = static_cast<const uint8_t *>(value->GetBytes());
  EXPECT_EQ(bytes[0], 0x11);
  EXPECT_EQ(bytes[8], 0x22);
  std::array<uint8_t, 16> replacement;
  replacement.fill(0x33);
  ASSERT_THAT_ERROR(
      layout.Write(vs0->id, RegisterValue(replacement, lldb::eByteOrderBig),
                   {{1, fp}, {3, extra}}),
      Succeeded());
  EXPECT_EQ(fp[0], 0x33);
  EXPECT_EQ(extra[0], 0x33);
  EXPECT_EQ(fp[8], 0);
  EXPECT_EQ(extra[8], 0);
}
