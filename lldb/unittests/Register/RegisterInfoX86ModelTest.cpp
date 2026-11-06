//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Plugins/Process/Windows/Common/RegisterModelWindows_x86.h"
#include "lldb/Register/Common/RegisterInfo_x86.h"
#include "lldb/Register/RegisterCodec.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <array>

using namespace lldb_private;
using namespace llvm;

TEST(RegisterInfoX86ModelTest, AliasesAndZeroExtensionAreArchitectureRules) {
  const RegisterStorageField locations[] = {{"rax", 8, 8}};
  ArchSpec arch("x86_64-unknown-freebsd");
  auto format = CreateX86RegisterModel(arch, locations, 24, true);
  const auto &description = *format.description;
  std::array<uint8_t, 16> bytes;
  bytes.fill(0xcc);
  MutableRegisterData bank{0, bytes};
  ASSERT_THAT_ERROR(RegisterCodec::Write(
                        description, format.layout, description.Find("eax")->id,
                        RegisterValue(uint32_t(0x12345678)), bank),
                    Succeeded());
  EXPECT_EQ(bytes[0], 0xcc);
  EXPECT_EQ(bytes[8], 0x78);
  EXPECT_EQ(bytes[9], 0x56);
  EXPECT_EQ(bytes[12], 0);
  EXPECT_EQ(bytes[15], 0);
  ASSERT_THAT_ERROR(RegisterCodec::Write(description, format.layout,
                                         description.Find("ah")->id,
                                         RegisterValue(uint8_t(0xab)), bank),
                    Succeeded());
  EXPECT_EQ(bytes[8], 0x78);
  EXPECT_EQ(bytes[9], 0xab);
  EXPECT_EQ(bytes[10], 0x34);
}

TEST(RegisterInfoX86ModelTest, PreservesSparseContextNumbersAndABI) {
  ArchSpec arch("x86_64-pc-windows");
  X86RegisterProfile profile;
  profile.gpr_aliases = profile.x87 = profile.avx = profile.mpx =
      profile.debug = false;
  RegisterInfo_x86 provider(arch, RegisterLayout(arch.GetByteOrder()), false,
                            X86RegisterABI::Windows, X86RegisterMode::Target,
                            profile);
  EXPECT_EQ(provider.GetRegisterCount(), 40u);
  EXPECT_EQ(provider.GetRegisterInfo()[24].kinds[lldb::eRegisterKindLLDB],
            lldb_xmm0_x86_64);
  EXPECT_EQ(provider.GetDescription()
                .Find("rcx")
                ->numbers[lldb::eRegisterKindGeneric],
            LLDB_REGNUM_GENERIC_ARG1);
  EXPECT_EQ(
      provider.GetDescription().Find("r9")->numbers[lldb::eRegisterKindGeneric],
      LLDB_REGNUM_GENERIC_ARG4);
  EXPECT_EQ(provider.GetRegisterSet(1)->registers[0], 24u);
  EXPECT_STREQ(provider.GetRegisterInfoByNumber(lldb_rip_x86_64)->name, "rip");
  EXPECT_EQ(provider.GetRegisterSetFromRegisterNumber(lldb_rip_x86_64), 0u);
}

TEST(RegisterInfoX86ModelTest, ArchitectureDescriptionNeedsNoOSLayout) {
  auto freebsd =
      RegisterInfo_x86::CreateDescription(ArchSpec("x86_64-unknown-freebsd"));
  auto linux =
      RegisterInfo_x86::CreateDescription(ArchSpec("x86_64-unknown-linux"));
  ASSERT_NE(freebsd->Find("rax"), nullptr);
  ASSERT_NE(linux->Find("rax"), nullptr);
  EXPECT_EQ(freebsd->Find("rax")->id, linux->Find("rax")->id);
  EXPECT_EQ(freebsd->Find("eax")->byte_size, 4u);
  EXPECT_EQ(freebsd->Find("eax")->zero_extend_parent, freebsd->Find("rax")->id);
  EXPECT_EQ(freebsd->Find("orig_rax"), nullptr);
}

TEST(RegisterInfoX86ModelTest, WindowsFrameX86PreservesRegisterView) {
  ArchSpec arch("i686-pc-windows");
  RegisterInfo_x86 info(
      arch, CreateWindowsX86RegisterModel(arch, X86RegisterMode::I386,
                                          WindowsX86ContextKind::Frame));
  const char *names[] = {"eax", "ebx", "ecx", "edx", "edi",
                         "esi", "ebp", "esp", "eip", "eflags"};
  ASSERT_EQ(info.GetRegisterCount(), 10u);
  for (size_t i = 0; i < std::size(names); ++i) {
    const auto &reg = info.GetRegisterInfo()[i];
    EXPECT_STREQ(reg.name, names[i]);
    EXPECT_EQ(reg.byte_offset, 0u);
    EXPECT_EQ(reg.value_regs, nullptr);
    EXPECT_EQ(reg.invalidate_regs, nullptr);
  }
  ASSERT_EQ(info.GetRegisterSetCount(), 1u);
  EXPECT_EQ(info.GetRegisterSet(0)->num_registers, 10u);
  for (uint32_t i = 0; i < 10; ++i)
    EXPECT_EQ(info.GetRegisterSet(0)->registers[i], i);
  const auto *flags = info.GetDescription().Find("eflags");
  ASSERT_NE(flags, nullptr);
  EXPECT_EQ(flags->format, lldb::eFormatBinary);
  EXPECT_EQ(flags->alt_name, "flags");
  EXPECT_EQ(flags->byte_size, 4u);
  EXPECT_EQ(info.GetDescription().Find("cs"), nullptr);
  EXPECT_EQ(info.GetDescription().Find("st0"), nullptr);
  EXPECT_EQ(info.GetDescription().Find("dr0"), nullptr);
  EXPECT_EQ(flags->numbers[lldb::eRegisterKindDWARF], 9u);
  EXPECT_EQ(flags->numbers[lldb::eRegisterKindEHFrame], 9u);
  EXPECT_EQ(flags->numbers[lldb::eRegisterKindLLDB], lldb_eflags_i386);
  EXPECT_EQ(info.GetDescription().Find("ax"), nullptr);
  EXPECT_EQ(info.GetDescription().Find("xmm0"), nullptr);
}

TEST(RegisterInfoX86ModelTest, WindowsFrameX64PreservesRegisterView) {
  ArchSpec arch("x86_64-pc-windows");
  RegisterInfo_x86 info(
      arch, CreateWindowsX86RegisterModel(arch, X86RegisterMode::X86_64,
                                          WindowsX86ContextKind::Frame));
  const char *names[] = {
      "rax",   "rbx",    "rcx",   "rdx",   "rdi",   "rsi",  "rbp",  "rsp",
      "r8",    "r9",     "r10",   "r11",   "r12",   "r13",  "r14",  "r15",
      "rip",   "eflags", "eax",   "ebx",   "ecx",   "edx",  "edi",  "esi",
      "ebp",   "esp",    "r8d",   "r9d",   "r10d",  "r11d", "r12d", "r13d",
      "r14d",  "r15d",   "ax",    "bx",    "cx",    "dx",   "di",   "si",
      "bp",    "sp",     "r8w",   "r9w",   "r10w",  "r11w", "r12w", "r13w",
      "r14w",  "r15w",   "ah",    "bh",    "ch",    "dh",   "al",   "bl",
      "cl",    "dl",     "dil",   "sil",   "bpl",   "spl",  "r8l",  "r9l",
      "r10l",  "r11l",   "r12l",  "r13l",  "r14l",  "r15l", "xmm0", "xmm1",
      "xmm2",  "xmm3",   "xmm4",  "xmm5",  "xmm6",  "xmm7", "xmm8", "xmm9",
      "xmm10", "xmm11",  "xmm12", "xmm13", "xmm14", "xmm15"};
  ASSERT_EQ(info.GetRegisterCount(), 86u);
  for (size_t i = 0; i < std::size(names); ++i) {
    const auto &reg = info.GetRegisterInfo()[i];
    EXPECT_STREQ(reg.name, names[i]);
    EXPECT_EQ(reg.byte_offset, 0u);
    EXPECT_EQ(reg.value_regs, nullptr);
    EXPECT_EQ(reg.invalidate_regs, nullptr);
  }
  ASSERT_EQ(info.GetRegisterSetCount(), 2u);
  EXPECT_EQ(info.GetRegisterSet(0)->num_registers, 70u);
  for (uint32_t i = 0; i < 70; ++i)
    EXPECT_EQ(info.GetRegisterSet(0)->registers[i], i);
  const auto *flags = info.GetDescription().Find("eflags");
  ASSERT_NE(flags, nullptr);
  EXPECT_EQ(flags->format, lldb::eFormatBinary);
  EXPECT_EQ(flags->alt_name, "flags");
  EXPECT_EQ(flags->byte_size, 8u);
  EXPECT_EQ(info.GetDescription().Find("cs"), nullptr);
  EXPECT_EQ(info.GetDescription().Find("st0"), nullptr);
  EXPECT_EQ(info.GetDescription().Find("dr0"), nullptr);
  EXPECT_EQ(flags->numbers[lldb::eRegisterKindDWARF], LLDB_INVALID_REGNUM);
  EXPECT_EQ(flags->numbers[lldb::eRegisterKindEHFrame], LLDB_INVALID_REGNUM);
  EXPECT_EQ(flags->numbers[lldb::eRegisterKindLLDB], lldb_rflags_x86_64);
  EXPECT_EQ(info.GetDescription().Find("eax")->byte_size, 4u);
  EXPECT_EQ(info.GetDescription().Find("ah")->byte_size, 1u);
  EXPECT_EQ(
      info.GetDescription().Find("rcx")->numbers[lldb::eRegisterKindGeneric],
      LLDB_REGNUM_GENERIC_ARG1);
  EXPECT_EQ(
      info.GetDescription().Find("r9")->numbers[lldb::eRegisterKindGeneric],
      LLDB_REGNUM_GENERIC_ARG4);
  EXPECT_EQ(info.GetDescription().Find("xmm0")->encoding, lldb::eEncodingUint);
  EXPECT_EQ(info.GetDescription().Find("xmm0")->format,
            lldb::eFormatVectorOfUInt64);
  EXPECT_EQ(info.GetRegisterSet(1)->num_registers, 16u);
  for (uint32_t i = 0; i < 16; ++i)
    EXPECT_EQ(info.GetRegisterSet(1)->registers[i], 70u + i);
}

TEST(RegisterInfoX86ModelTest, WindowsNativeProfilesRetainSegments) {
  RegisterInfo_x86 info_i386(
      ArchSpec("i686-pc-windows"),
      CreateWindowsX86RegisterModel(ArchSpec("i686-pc-windows"),
                                    X86RegisterMode::I386));
  RegisterInfo_x86 info_x64(
      ArchSpec("x86_64-pc-windows"),
      CreateWindowsX86RegisterModel(ArchSpec("x86_64-pc-windows"),
                                    X86RegisterMode::X86_64));
  EXPECT_EQ(info_i386.GetRegisterCount(), 16u);
  EXPECT_EQ(info_x64.GetRegisterCount(), 40u);
  EXPECT_NE(info_i386.GetDescription().Find("cs"), nullptr);
  EXPECT_NE(info_x64.GetDescription().Find("cs"), nullptr);
  EXPECT_EQ(info_x64.GetDescription().Find("eax"), nullptr);
  EXPECT_NE(info_x64.GetDescription().Find("xmm0"), nullptr);
}
