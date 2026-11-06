//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#define SVE_OFFSET_VG 0
static uint32_t g_sve_s0_invalidates[] = {sve_z0_arm64, fpu_v0_arm64, fpu_d0_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s1_invalidates[] = {sve_z1_arm64, fpu_v1_arm64, fpu_d1_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s2_invalidates[] = {sve_z2_arm64, fpu_v2_arm64, fpu_d2_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s3_invalidates[] = {sve_z3_arm64, fpu_v3_arm64, fpu_d3_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s4_invalidates[] = {sve_z4_arm64, fpu_v4_arm64, fpu_d4_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s5_invalidates[] = {sve_z5_arm64, fpu_v5_arm64, fpu_d5_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s6_invalidates[] = {sve_z6_arm64, fpu_v6_arm64, fpu_d6_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s7_invalidates[] = {sve_z7_arm64, fpu_v7_arm64, fpu_d7_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s8_invalidates[] = {sve_z8_arm64, fpu_v8_arm64, fpu_d8_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s9_invalidates[] = {sve_z9_arm64, fpu_v9_arm64, fpu_d9_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_s10_invalidates[] = {sve_z10_arm64, fpu_v10_arm64, fpu_d10_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s11_invalidates[] = {sve_z11_arm64, fpu_v11_arm64, fpu_d11_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s12_invalidates[] = {sve_z12_arm64, fpu_v12_arm64, fpu_d12_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s13_invalidates[] = {sve_z13_arm64, fpu_v13_arm64, fpu_d13_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s14_invalidates[] = {sve_z14_arm64, fpu_v14_arm64, fpu_d14_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s15_invalidates[] = {sve_z15_arm64, fpu_v15_arm64, fpu_d15_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s16_invalidates[] = {sve_z16_arm64, fpu_v16_arm64, fpu_d16_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s17_invalidates[] = {sve_z17_arm64, fpu_v17_arm64, fpu_d17_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s18_invalidates[] = {sve_z18_arm64, fpu_v18_arm64, fpu_d18_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s19_invalidates[] = {sve_z19_arm64, fpu_v19_arm64, fpu_d19_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s20_invalidates[] = {sve_z20_arm64, fpu_v20_arm64, fpu_d20_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s21_invalidates[] = {sve_z21_arm64, fpu_v21_arm64, fpu_d21_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s22_invalidates[] = {sve_z22_arm64, fpu_v22_arm64, fpu_d22_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s23_invalidates[] = {sve_z23_arm64, fpu_v23_arm64, fpu_d23_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s24_invalidates[] = {sve_z24_arm64, fpu_v24_arm64, fpu_d24_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s25_invalidates[] = {sve_z25_arm64, fpu_v25_arm64, fpu_d25_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s26_invalidates[] = {sve_z26_arm64, fpu_v26_arm64, fpu_d26_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s27_invalidates[] = {sve_z27_arm64, fpu_v27_arm64, fpu_d27_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s28_invalidates[] = {sve_z28_arm64, fpu_v28_arm64, fpu_d28_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s29_invalidates[] = {sve_z29_arm64, fpu_v29_arm64, fpu_d29_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s30_invalidates[] = {sve_z30_arm64, fpu_v30_arm64, fpu_d30_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_s31_invalidates[] = {sve_z31_arm64, fpu_v31_arm64, fpu_d31_arm64,
                                           LLDB_INVALID_REGNUM};

static uint32_t g_sve_d0_invalidates[] = {sve_z0_arm64, fpu_v0_arm64, fpu_s0_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d1_invalidates[] = {sve_z1_arm64, fpu_v1_arm64, fpu_s1_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d2_invalidates[] = {sve_z2_arm64, fpu_v2_arm64, fpu_s2_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d3_invalidates[] = {sve_z3_arm64, fpu_v3_arm64, fpu_s3_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d4_invalidates[] = {sve_z4_arm64, fpu_v4_arm64, fpu_s4_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d5_invalidates[] = {sve_z5_arm64, fpu_v5_arm64, fpu_s5_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d6_invalidates[] = {sve_z6_arm64, fpu_v6_arm64, fpu_s6_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d7_invalidates[] = {sve_z7_arm64, fpu_v7_arm64, fpu_s7_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d8_invalidates[] = {sve_z8_arm64, fpu_v8_arm64, fpu_s8_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d9_invalidates[] = {sve_z9_arm64, fpu_v9_arm64, fpu_s9_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_d10_invalidates[] = {sve_z10_arm64, fpu_v10_arm64, fpu_s10_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d11_invalidates[] = {sve_z11_arm64, fpu_v11_arm64, fpu_s11_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d12_invalidates[] = {sve_z12_arm64, fpu_v12_arm64, fpu_s12_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d13_invalidates[] = {sve_z13_arm64, fpu_v13_arm64, fpu_s13_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d14_invalidates[] = {sve_z14_arm64, fpu_v14_arm64, fpu_s14_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d15_invalidates[] = {sve_z15_arm64, fpu_v15_arm64, fpu_s15_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d16_invalidates[] = {sve_z16_arm64, fpu_v16_arm64, fpu_s16_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d17_invalidates[] = {sve_z17_arm64, fpu_v17_arm64, fpu_s17_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d18_invalidates[] = {sve_z18_arm64, fpu_v18_arm64, fpu_s18_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d19_invalidates[] = {sve_z19_arm64, fpu_v19_arm64, fpu_s19_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d20_invalidates[] = {sve_z20_arm64, fpu_v20_arm64, fpu_s20_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d21_invalidates[] = {sve_z21_arm64, fpu_v21_arm64, fpu_s21_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d22_invalidates[] = {sve_z22_arm64, fpu_v22_arm64, fpu_s22_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d23_invalidates[] = {sve_z23_arm64, fpu_v23_arm64, fpu_s23_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d24_invalidates[] = {sve_z24_arm64, fpu_v24_arm64, fpu_s24_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d25_invalidates[] = {sve_z25_arm64, fpu_v25_arm64, fpu_s25_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d26_invalidates[] = {sve_z26_arm64, fpu_v26_arm64, fpu_s26_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d27_invalidates[] = {sve_z27_arm64, fpu_v27_arm64, fpu_s27_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d28_invalidates[] = {sve_z28_arm64, fpu_v28_arm64, fpu_s28_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d29_invalidates[] = {sve_z29_arm64, fpu_v29_arm64, fpu_s29_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d30_invalidates[] = {sve_z30_arm64, fpu_v30_arm64, fpu_s30_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_d31_invalidates[] = {sve_z31_arm64, fpu_v31_arm64, fpu_s31_arm64,
                                           LLDB_INVALID_REGNUM};

static uint32_t g_sve_v0_invalidates[] = {sve_z0_arm64, fpu_d0_arm64, fpu_s0_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v1_invalidates[] = {sve_z1_arm64, fpu_d1_arm64, fpu_s1_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v2_invalidates[] = {sve_z2_arm64, fpu_d2_arm64, fpu_s2_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v3_invalidates[] = {sve_z3_arm64, fpu_d3_arm64, fpu_s3_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v4_invalidates[] = {sve_z4_arm64, fpu_d4_arm64, fpu_s4_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v5_invalidates[] = {sve_z5_arm64, fpu_d5_arm64, fpu_s5_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v6_invalidates[] = {sve_z6_arm64, fpu_d6_arm64, fpu_s6_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v7_invalidates[] = {sve_z7_arm64, fpu_d7_arm64, fpu_s7_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v8_invalidates[] = {sve_z8_arm64, fpu_d8_arm64, fpu_s8_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v9_invalidates[] = {sve_z9_arm64, fpu_d9_arm64, fpu_s9_arm64,
                                          LLDB_INVALID_REGNUM};
static uint32_t g_sve_v10_invalidates[] = {sve_z10_arm64, fpu_d10_arm64, fpu_s10_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v11_invalidates[] = {sve_z11_arm64, fpu_d11_arm64, fpu_s11_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v12_invalidates[] = {sve_z12_arm64, fpu_d12_arm64, fpu_s12_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v13_invalidates[] = {sve_z13_arm64, fpu_d13_arm64, fpu_s13_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v14_invalidates[] = {sve_z14_arm64, fpu_d14_arm64, fpu_s14_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v15_invalidates[] = {sve_z15_arm64, fpu_d15_arm64, fpu_s15_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v16_invalidates[] = {sve_z16_arm64, fpu_d16_arm64, fpu_s16_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v17_invalidates[] = {sve_z17_arm64, fpu_d17_arm64, fpu_s17_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v18_invalidates[] = {sve_z18_arm64, fpu_d18_arm64, fpu_s18_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v19_invalidates[] = {sve_z19_arm64, fpu_d19_arm64, fpu_s19_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v20_invalidates[] = {sve_z20_arm64, fpu_d20_arm64, fpu_s20_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v21_invalidates[] = {sve_z21_arm64, fpu_d21_arm64, fpu_s21_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v22_invalidates[] = {sve_z22_arm64, fpu_d22_arm64, fpu_s22_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v23_invalidates[] = {sve_z23_arm64, fpu_d23_arm64, fpu_s23_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v24_invalidates[] = {sve_z24_arm64, fpu_d24_arm64, fpu_s24_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v25_invalidates[] = {sve_z25_arm64, fpu_d25_arm64, fpu_s25_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v26_invalidates[] = {sve_z26_arm64, fpu_d26_arm64, fpu_s26_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v27_invalidates[] = {sve_z27_arm64, fpu_d27_arm64, fpu_s27_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v28_invalidates[] = {sve_z28_arm64, fpu_d28_arm64, fpu_s28_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v29_invalidates[] = {sve_z29_arm64, fpu_d29_arm64, fpu_s29_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v30_invalidates[] = {sve_z30_arm64, fpu_d30_arm64, fpu_s30_arm64,
                                           LLDB_INVALID_REGNUM};
static uint32_t g_sve_v31_invalidates[] = {sve_z31_arm64, fpu_d31_arm64, fpu_s31_arm64,
                                           LLDB_INVALID_REGNUM};

static uint32_t g_contained_z0[] = {sve_z0_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z1[] = {sve_z1_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z2[] = {sve_z2_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z3[] = {sve_z3_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z4[] = {sve_z4_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z5[] = {sve_z5_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z6[] = {sve_z6_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z7[] = {sve_z7_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z8[] = {sve_z8_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z9[] = {sve_z9_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z10[] = {sve_z10_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z11[] = {sve_z11_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z12[] = {sve_z12_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z13[] = {sve_z13_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z14[] = {sve_z14_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z15[] = {sve_z15_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z16[] = {sve_z16_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z17[] = {sve_z17_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z18[] = {sve_z18_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z19[] = {sve_z19_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z20[] = {sve_z20_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z21[] = {sve_z21_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z22[] = {sve_z22_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z23[] = {sve_z23_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z24[] = {sve_z24_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z25[] = {sve_z25_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z26[] = {sve_z26_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z27[] = {sve_z27_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z28[] = {sve_z28_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z29[] = {sve_z29_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z30[] = {sve_z30_arm64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_z31[] = {sve_z31_arm64, LLDB_INVALID_REGNUM};

#define VG_OFFSET_NAME(reg) SVE_OFFSET_VG

#define SVE_REG_KIND(reg) MISC_KIND(reg, sve, LLDB_INVALID_REGNUM)
#define MISC_VG_KIND(lldb_kind) MISC_KIND(vg, sve, LLDB_INVALID_REGNUM)

// Default offset SVE Z registers and all corresponding pseudo registers
// ( S, D and V registers) is zero and will be configured during execution.

// clang-format off

// Defines sve pseudo vector (V) register with 16-byte size
#define DEFINE_VREG_SVE(vreg, zreg)                                            \
  {                                                                            \
    #vreg, nullptr, 16, 0, lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,  \
        VREG_KIND(vreg), g_contained_##zreg, g_sve_##vreg##_invalidates,       \
        nullptr,                                                               \
  }

// Defines S and D pseudo registers mapping over corresponding vector register
#define DEFINE_FPU_PSEUDO_SVE(reg, size, zreg)                                 \
  {                                                                            \
    #reg, nullptr, size, 0, lldb::eEncodingIEEE754, lldb::eFormatFloat,        \
        LLDB_KIND(fpu_##reg##_arm64), g_contained_##zreg, g_sve_##reg##_invalidates,   \
        nullptr,                                                               \
  }

// Defines a Z vector register with 16-byte default size
#define DEFINE_ZREG(reg)                                                       \
  {                                                                            \
    #reg, nullptr, 16, 0, lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,   \
        SVE_REG_KIND(reg), nullptr, nullptr, nullptr,                          \
  }

// Defines a P vector register with 2-byte default size
#define DEFINE_PREG(reg)                                                       \
  {                                                                            \
    #reg, nullptr, 2, 0, lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,    \
        SVE_REG_KIND(reg), nullptr, nullptr, nullptr,                          \
  }

static RegisterInfo g_register_infos_arm64_sve_le[] = {
    // DEFINE_GPR64(name, GENERIC KIND)
    DEFINE_GPR64(x0, LLDB_REGNUM_GENERIC_ARG1),
    DEFINE_GPR64(x1, LLDB_REGNUM_GENERIC_ARG2),
    DEFINE_GPR64(x2, LLDB_REGNUM_GENERIC_ARG3),
    DEFINE_GPR64(x3, LLDB_REGNUM_GENERIC_ARG4),
    DEFINE_GPR64(x4, LLDB_REGNUM_GENERIC_ARG5),
    DEFINE_GPR64(x5, LLDB_REGNUM_GENERIC_ARG6),
    DEFINE_GPR64(x6, LLDB_REGNUM_GENERIC_ARG7),
    DEFINE_GPR64(x7, LLDB_REGNUM_GENERIC_ARG8),
    DEFINE_GPR64(x8, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x9, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x10, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x11, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x12, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x13, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x14, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x15, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x16, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x17, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x18, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x19, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x20, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x21, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x22, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x23, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x24, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x25, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x26, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x27, LLDB_INVALID_REGNUM),
    DEFINE_GPR64(x28, LLDB_INVALID_REGNUM),
    // DEFINE_GPR64(name, GENERIC KIND)
    DEFINE_GPR64_ALT(fp, x29, LLDB_REGNUM_GENERIC_FP),
    DEFINE_GPR64_ALT(lr, x30, LLDB_REGNUM_GENERIC_RA),
    DEFINE_GPR64_ALT(sp, x31, LLDB_REGNUM_GENERIC_SP),
    DEFINE_GPR64(pc, LLDB_REGNUM_GENERIC_PC),

    DEFINE_GPR_CPSR,

    // DEFINE_GPR32(name, parent name)
    DEFINE_GPR32(w0, x0),
    DEFINE_GPR32(w1, x1),
    DEFINE_GPR32(w2, x2),
    DEFINE_GPR32(w3, x3),
    DEFINE_GPR32(w4, x4),
    DEFINE_GPR32(w5, x5),
    DEFINE_GPR32(w6, x6),
    DEFINE_GPR32(w7, x7),
    DEFINE_GPR32(w8, x8),
    DEFINE_GPR32(w9, x9),
    DEFINE_GPR32(w10, x10),
    DEFINE_GPR32(w11, x11),
    DEFINE_GPR32(w12, x12),
    DEFINE_GPR32(w13, x13),
    DEFINE_GPR32(w14, x14),
    DEFINE_GPR32(w15, x15),
    DEFINE_GPR32(w16, x16),
    DEFINE_GPR32(w17, x17),
    DEFINE_GPR32(w18, x18),
    DEFINE_GPR32(w19, x19),
    DEFINE_GPR32(w20, x20),
    DEFINE_GPR32(w21, x21),
    DEFINE_GPR32(w22, x22),
    DEFINE_GPR32(w23, x23),
    DEFINE_GPR32(w24, x24),
    DEFINE_GPR32(w25, x25),
    DEFINE_GPR32(w26, x26),
    DEFINE_GPR32(w27, x27),
    DEFINE_GPR32(w28, x28),

    // DEFINE_VREG_SVE(v register, z register)
    DEFINE_VREG_SVE(v0, z0),
    DEFINE_VREG_SVE(v1, z1),
    DEFINE_VREG_SVE(v2, z2),
    DEFINE_VREG_SVE(v3, z3),
    DEFINE_VREG_SVE(v4, z4),
    DEFINE_VREG_SVE(v5, z5),
    DEFINE_VREG_SVE(v6, z6),
    DEFINE_VREG_SVE(v7, z7),
    DEFINE_VREG_SVE(v8, z8),
    DEFINE_VREG_SVE(v9, z9),
    DEFINE_VREG_SVE(v10, z10),
    DEFINE_VREG_SVE(v11, z11),
    DEFINE_VREG_SVE(v12, z12),
    DEFINE_VREG_SVE(v13, z13),
    DEFINE_VREG_SVE(v14, z14),
    DEFINE_VREG_SVE(v15, z15),
    DEFINE_VREG_SVE(v16, z16),
    DEFINE_VREG_SVE(v17, z17),
    DEFINE_VREG_SVE(v18, z18),
    DEFINE_VREG_SVE(v19, z19),
    DEFINE_VREG_SVE(v20, z20),
    DEFINE_VREG_SVE(v21, z21),
    DEFINE_VREG_SVE(v22, z22),
    DEFINE_VREG_SVE(v23, z23),
    DEFINE_VREG_SVE(v24, z24),
    DEFINE_VREG_SVE(v25, z25),
    DEFINE_VREG_SVE(v26, z26),
    DEFINE_VREG_SVE(v27, z27),
    DEFINE_VREG_SVE(v28, z28),
    DEFINE_VREG_SVE(v29, z29),
    DEFINE_VREG_SVE(v30, z30),
    DEFINE_VREG_SVE(v31, z31),

    // DEFINE_FPU_PSEUDO(name, size, ENDIAN OFFSET, parent register)
    DEFINE_FPU_PSEUDO_SVE(s0, 4, z0),
    DEFINE_FPU_PSEUDO_SVE(s1, 4, z1),
    DEFINE_FPU_PSEUDO_SVE(s2, 4, z2),
    DEFINE_FPU_PSEUDO_SVE(s3, 4, z3),
    DEFINE_FPU_PSEUDO_SVE(s4, 4, z4),
    DEFINE_FPU_PSEUDO_SVE(s5, 4, z5),
    DEFINE_FPU_PSEUDO_SVE(s6, 4, z6),
    DEFINE_FPU_PSEUDO_SVE(s7, 4, z7),
    DEFINE_FPU_PSEUDO_SVE(s8, 4, z8),
    DEFINE_FPU_PSEUDO_SVE(s9, 4, z9),
    DEFINE_FPU_PSEUDO_SVE(s10, 4, z10),
    DEFINE_FPU_PSEUDO_SVE(s11, 4, z11),
    DEFINE_FPU_PSEUDO_SVE(s12, 4, z12),
    DEFINE_FPU_PSEUDO_SVE(s13, 4, z13),
    DEFINE_FPU_PSEUDO_SVE(s14, 4, z14),
    DEFINE_FPU_PSEUDO_SVE(s15, 4, z15),
    DEFINE_FPU_PSEUDO_SVE(s16, 4, z16),
    DEFINE_FPU_PSEUDO_SVE(s17, 4, z17),
    DEFINE_FPU_PSEUDO_SVE(s18, 4, z18),
    DEFINE_FPU_PSEUDO_SVE(s19, 4, z19),
    DEFINE_FPU_PSEUDO_SVE(s20, 4, z20),
    DEFINE_FPU_PSEUDO_SVE(s21, 4, z21),
    DEFINE_FPU_PSEUDO_SVE(s22, 4, z22),
    DEFINE_FPU_PSEUDO_SVE(s23, 4, z23),
    DEFINE_FPU_PSEUDO_SVE(s24, 4, z24),
    DEFINE_FPU_PSEUDO_SVE(s25, 4, z25),
    DEFINE_FPU_PSEUDO_SVE(s26, 4, z26),
    DEFINE_FPU_PSEUDO_SVE(s27, 4, z27),
    DEFINE_FPU_PSEUDO_SVE(s28, 4, z28),
    DEFINE_FPU_PSEUDO_SVE(s29, 4, z29),
    DEFINE_FPU_PSEUDO_SVE(s30, 4, z30),
    DEFINE_FPU_PSEUDO_SVE(s31, 4, z31),

    DEFINE_FPU_PSEUDO_SVE(d0, 8, z0),
    DEFINE_FPU_PSEUDO_SVE(d1, 8, z1),
    DEFINE_FPU_PSEUDO_SVE(d2, 8, z2),
    DEFINE_FPU_PSEUDO_SVE(d3, 8, z3),
    DEFINE_FPU_PSEUDO_SVE(d4, 8, z4),
    DEFINE_FPU_PSEUDO_SVE(d5, 8, z5),
    DEFINE_FPU_PSEUDO_SVE(d6, 8, z6),
    DEFINE_FPU_PSEUDO_SVE(d7, 8, z7),
    DEFINE_FPU_PSEUDO_SVE(d8, 8, z8),
    DEFINE_FPU_PSEUDO_SVE(d9, 8, z9),
    DEFINE_FPU_PSEUDO_SVE(d10, 8, z10),
    DEFINE_FPU_PSEUDO_SVE(d11, 8, z11),
    DEFINE_FPU_PSEUDO_SVE(d12, 8, z12),
    DEFINE_FPU_PSEUDO_SVE(d13, 8, z13),
    DEFINE_FPU_PSEUDO_SVE(d14, 8, z14),
    DEFINE_FPU_PSEUDO_SVE(d15, 8, z15),
    DEFINE_FPU_PSEUDO_SVE(d16, 8, z16),
    DEFINE_FPU_PSEUDO_SVE(d17, 8, z17),
    DEFINE_FPU_PSEUDO_SVE(d18, 8, z18),
    DEFINE_FPU_PSEUDO_SVE(d19, 8, z19),
    DEFINE_FPU_PSEUDO_SVE(d20, 8, z20),
    DEFINE_FPU_PSEUDO_SVE(d21, 8, z21),
    DEFINE_FPU_PSEUDO_SVE(d22, 8, z22),
    DEFINE_FPU_PSEUDO_SVE(d23, 8, z23),
    DEFINE_FPU_PSEUDO_SVE(d24, 8, z24),
    DEFINE_FPU_PSEUDO_SVE(d25, 8, z25),
    DEFINE_FPU_PSEUDO_SVE(d26, 8, z26),
    DEFINE_FPU_PSEUDO_SVE(d27, 8, z27),
    DEFINE_FPU_PSEUDO_SVE(d28, 8, z28),
    DEFINE_FPU_PSEUDO_SVE(d29, 8, z29),
    DEFINE_FPU_PSEUDO_SVE(d30, 8, z30),
    DEFINE_FPU_PSEUDO_SVE(d31, 8, z31),

    // DEFINE_MISC_LLDB_REGS(name, size, TYPE, lldb kind)
    DEFINE_MISC_LLDB_REGS(fpsr, 4, FPU, fpu_fpsr_arm64),
    DEFINE_MISC_LLDB_REGS(fpcr, 4, FPU, fpu_fpcr_arm64),

    DEFINE_MISC_REGS(vg, 8, VG, sve_vg_arm64),
    // DEFINE_ZREG(name)
    DEFINE_ZREG(z0),
    DEFINE_ZREG(z1),
    DEFINE_ZREG(z2),
    DEFINE_ZREG(z3),
    DEFINE_ZREG(z4),
    DEFINE_ZREG(z5),
    DEFINE_ZREG(z6),
    DEFINE_ZREG(z7),
    DEFINE_ZREG(z8),
    DEFINE_ZREG(z9),
    DEFINE_ZREG(z10),
    DEFINE_ZREG(z11),
    DEFINE_ZREG(z12),
    DEFINE_ZREG(z13),
    DEFINE_ZREG(z14),
    DEFINE_ZREG(z15),
    DEFINE_ZREG(z16),
    DEFINE_ZREG(z17),
    DEFINE_ZREG(z18),
    DEFINE_ZREG(z19),
    DEFINE_ZREG(z20),
    DEFINE_ZREG(z21),
    DEFINE_ZREG(z22),
    DEFINE_ZREG(z23),
    DEFINE_ZREG(z24),
    DEFINE_ZREG(z25),
    DEFINE_ZREG(z26),
    DEFINE_ZREG(z27),
    DEFINE_ZREG(z28),
    DEFINE_ZREG(z29),
    DEFINE_ZREG(z30),
    DEFINE_ZREG(z31),

    // DEFINE_PREG(name)
    DEFINE_PREG(p0),
    DEFINE_PREG(p1),
    DEFINE_PREG(p2),
    DEFINE_PREG(p3),
    DEFINE_PREG(p4),
    DEFINE_PREG(p5),
    DEFINE_PREG(p6),
    DEFINE_PREG(p7),
    DEFINE_PREG(p8),
    DEFINE_PREG(p9),
    DEFINE_PREG(p10),
    DEFINE_PREG(p11),
    DEFINE_PREG(p12),
    DEFINE_PREG(p13),
    DEFINE_PREG(p14),
    DEFINE_PREG(p15),

    // DEFINE FFR
    DEFINE_PREG(ffr)
    // clang-format on
};


