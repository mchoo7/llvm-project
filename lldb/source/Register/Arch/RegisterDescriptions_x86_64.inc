//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// Private architecture-description generator. No native layout inputs.
#define GPR_OFFSET(...) 0
#define FPR_OFFSET(...) 0
#define YMM_OFFSET(...) 0
#define BNDR_OFFSET(...) 0
#define BNDC_OFFSET(...) 0
#define DR_OFFSET(...) 0
#define DR_SIZE word_size
// Number of bytes needed to represent a FPR.
#define FPR_SIZE(reg) FPRValueByteSize(#reg)

// Number of bytes needed to represent the i'th FP register.
#define FP_SIZE 10

// Number of bytes needed to represent an XMM register.
#define XMM_SIZE 16

// Number of bytes needed to represent a YMM register.
#define YMM_SIZE 32

// Number of bytes needed to represent MPX registers.
#define BNDR_SIZE 16
#define BNDC_SIZE 8


// RegisterKind: EHFrame, DWARF, Generic, Process Plugin, LLDB

// Value widths and aliases are independent of storage slots.
#define DEFINE_GPR(reg, alt, kind1, kind2, kind3, kind4)                       \
  {                                                                            \
    #reg, alt, word_size,                                  \
                      GPR_OFFSET(reg), lldb::eEncodingUint, lldb::eFormatHex,              \
                                 {kind1, kind2, kind3, kind4,                  \
                                  lldb_##reg##_x86_64 },                       \
                                  nullptr, nullptr, nullptr,                   \
  }

#define DEFINE_FPR(name, reg, kind1, kind2, kind3, kind4)                      \
  {                                                                            \
    #name, nullptr, FPR_SIZE(reg), FPR_OFFSET(reg), lldb::eEncodingUint, lldb::eFormatHex, \
                                           {kind1, kind2, kind3, kind4,        \
                                            lldb_##name##_x86_64 },            \
                                            nullptr, nullptr, nullptr,         \
  }

#define DEFINE_FP_ST(reg, i)                                                   \
  {                                                                            \
    #reg #i, nullptr, FP_SIZE,                                                 \
        LLVM_EXTENSION FPR_OFFSET(                                             \
            stmm[i]), lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,                   \
            {dwarf_st##i##_x86_64, dwarf_st##i##_x86_64, LLDB_INVALID_REGNUM,  \
             LLDB_INVALID_REGNUM, lldb_st##i##_x86_64 },                       \
             nullptr, nullptr, nullptr,                                        \
  }

#define DEFINE_FP_MM(reg, i, streg)                                            \
  {                                                                            \
    #reg #i, nullptr, 8, LLVM_EXTENSION FPR_OFFSET(stmm[i]),    \
    lldb::eEncodingUint, lldb::eFormatHex,                                                 \
    {dwarf_mm##i##_x86_64, dwarf_mm##i##_x86_64, LLDB_INVALID_REGNUM,          \
     LLDB_INVALID_REGNUM, lldb_mm##i##_x86_64 },                               \
    x86_register_info::g_contained_##streg##_64,                               \
    x86_register_info::g_invalidate_##streg##_64,                              \
    nullptr,                                                                   \
  }

#define DEFINE_XMM(reg, i)                                                     \
  {                                                                            \
    #reg #i, nullptr, XMM_SIZE,                                                \
        LLVM_EXTENSION FPR_OFFSET(                                             \
            reg[i]), lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,                    \
            {dwarf_##reg##i##_x86_64, dwarf_##reg##i##_x86_64,                 \
             LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                         \
             lldb_##reg##i##_x86_64 },                                         \
             nullptr, nullptr, nullptr,                                        \
  }

#define DEFINE_YMM(reg, i)                                                     \
  {                                                                            \
    #reg #i, nullptr, YMM_SIZE,                                                \
        LLVM_EXTENSION YMM_OFFSET(i), lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,   \
                                  {dwarf_##reg##i##h_x86_64,                   \
                                   dwarf_##reg##i##h_x86_64,                   \
                                   LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,   \
                                   lldb_##reg##i##_x86_64 },                   \
                                   nullptr, nullptr, nullptr,                  \
  }

#define DEFINE_BNDR(reg, i)                                                    \
  {                                                                            \
    #reg #i, nullptr, BNDR_SIZE,                                               \
        LLVM_EXTENSION BNDR_OFFSET(i), lldb::eEncodingVector, lldb::eFormatVectorOfUInt64, \
                                   {dwarf_##reg##i##_x86_64,                   \
                                    dwarf_##reg##i##_x86_64,                   \
                                    LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,  \
                                    lldb_##reg##i##_x86_64 },                  \
                                    nullptr, nullptr, nullptr,                 \
  }

#define DEFINE_BNDC(name, i)                                                   \
  {                                                                            \
    #name, nullptr, BNDC_SIZE,                                                 \
        LLVM_EXTENSION BNDC_OFFSET(i), lldb::eEncodingVector, lldb::eFormatVectorOfUInt8,  \
        {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,        \
         LLDB_INVALID_REGNUM, lldb_##name##_x86_64 },                          \
         nullptr, nullptr, nullptr,                                            \
  }

#define DEFINE_DR(reg, i)                                                      \
  {                                                                            \
    #reg #i, nullptr, DR_SIZE,                                                 \
        DR_OFFSET(i), lldb::eEncodingUint, lldb::eFormatHex,                               \
                  {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                   \
                   LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                   \
                   lldb_##reg##i##_x86_64 },                                   \
                   nullptr, nullptr, nullptr,                                  \
  }

#define DEFINE_GPR_PSEUDO_32(reg32, reg64)                                     \
  {                                                                            \
    #reg32, nullptr, 4,                                                        \
        GPR_OFFSET(reg64), lldb::eEncodingUint, lldb::eFormatHex,                          \
                   {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    lldb_##reg32##_x86_64 },                                   \
                    x86_register_info::g_contained_##reg64,                    \
                    x86_register_info::g_invalidate_##reg64,                   \
                    nullptr,                                                   \
  }

#define DEFINE_GPR_PSEUDO_16(reg16, reg64)                                     \
  {                                                                            \
    #reg16, nullptr, 2,                                                        \
        GPR_OFFSET(reg64), lldb::eEncodingUint, lldb::eFormatHex,                          \
                   {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    lldb_##reg16##_x86_64 },                                   \
                    x86_register_info::g_contained_##reg64,                    \
                    x86_register_info::g_invalidate_##reg64,                   \
                    nullptr,                                                   \
  }

#define DEFINE_GPR_PSEUDO_8H(reg8, reg64)                                      \
  {                                                                            \
    #reg8, nullptr, 1,                                                         \
        GPR_OFFSET(reg64) + 1, lldb::eEncodingUint, lldb::eFormatHex,                      \
                   {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    lldb_##reg8##_x86_64 },                                    \
                    x86_register_info::g_contained_##reg64,                    \
                    x86_register_info::g_invalidate_##reg64,                   \
                    nullptr,                                                   \
  }

#define DEFINE_GPR_PSEUDO_8L(reg8, reg64)                                      \
  {                                                                            \
    #reg8, nullptr, 1,                                                         \
        GPR_OFFSET(reg64), lldb::eEncodingUint, lldb::eFormatHex,                          \
                   {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,                  \
                    lldb_##reg8##_x86_64 },                                    \
                    x86_register_info::g_contained_##reg64,                    \
                    x86_register_info::g_invalidate_##reg64,                   \
                    nullptr                                                    \
  }

#define DEFINE_FPR_32(name, reg, kind1, kind2, kind3, kind4, reg64)            \
  {                                                                            \
    #name, nullptr, FPR_SIZE(reg), FPR_OFFSET(reg), lldb::eEncodingUint, lldb::eFormatHex, \
    {kind1, kind2, kind3, kind4, lldb_##name##_x86_64 },                       \
    x86_register_info::g_contained_##reg64,                                    \
    x86_register_info::g_invalidate_##reg64,                                   \
    nullptr,                                                                   \
  }

// clang-format off
static RegisterInfo g_register_infos_x86_64[] = {
// General purpose registers     EH_Frame              DWARF                 Generic                     Process Plugin
//  ===========================  ==================    ================      =========================   ====================
    DEFINE_GPR(rax,    nullptr,  dwarf_rax_x86_64,     dwarf_rax_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(rbx,    nullptr,  dwarf_rbx_x86_64,     dwarf_rbx_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(rcx,    nullptr,  dwarf_rcx_x86_64,     dwarf_rcx_x86_64,     LLDB_REGNUM_GENERIC_ARG4,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rdx,    nullptr,  dwarf_rdx_x86_64,     dwarf_rdx_x86_64,     LLDB_REGNUM_GENERIC_ARG3,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rdi,    nullptr,  dwarf_rdi_x86_64,     dwarf_rdi_x86_64,     LLDB_REGNUM_GENERIC_ARG1,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rsi,    nullptr,  dwarf_rsi_x86_64,     dwarf_rsi_x86_64,     LLDB_REGNUM_GENERIC_ARG2,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rbp,    nullptr,  dwarf_rbp_x86_64,     dwarf_rbp_x86_64,     LLDB_REGNUM_GENERIC_FP,     LLDB_INVALID_REGNUM),
    DEFINE_GPR(rsp,    nullptr,  dwarf_rsp_x86_64,     dwarf_rsp_x86_64,     LLDB_REGNUM_GENERIC_SP,     LLDB_INVALID_REGNUM),
    DEFINE_GPR(r8,     nullptr,  dwarf_r8_x86_64,      dwarf_r8_x86_64,      LLDB_REGNUM_GENERIC_ARG5,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(r9,     nullptr,  dwarf_r9_x86_64,      dwarf_r9_x86_64,      LLDB_REGNUM_GENERIC_ARG6,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(r10,    nullptr,  dwarf_r10_x86_64,     dwarf_r10_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r11,    nullptr,  dwarf_r11_x86_64,     dwarf_r11_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r12,    nullptr,  dwarf_r12_x86_64,     dwarf_r12_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r13,    nullptr,  dwarf_r13_x86_64,     dwarf_r13_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r14,    nullptr,  dwarf_r14_x86_64,     dwarf_r14_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r15,    nullptr,  dwarf_r15_x86_64,     dwarf_r15_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(rip,    nullptr,  dwarf_rip_x86_64,     dwarf_rip_x86_64,     LLDB_REGNUM_GENERIC_PC,     LLDB_INVALID_REGNUM),
    DEFINE_GPR(rflags, nullptr,  dwarf_rflags_x86_64,  dwarf_rflags_x86_64,  LLDB_REGNUM_GENERIC_FLAGS,  LLDB_INVALID_REGNUM),
    DEFINE_GPR(cs,     nullptr,  dwarf_cs_x86_64,      dwarf_cs_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(fs,     nullptr,  dwarf_fs_x86_64,      dwarf_fs_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(gs,     nullptr,  dwarf_gs_x86_64,      dwarf_gs_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(ss,     nullptr,  dwarf_ss_x86_64,      dwarf_ss_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(ds,     nullptr,  dwarf_ds_x86_64,      dwarf_ds_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(es,     nullptr,  dwarf_es_x86_64,      dwarf_es_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),

    DEFINE_GPR_PSEUDO_32(eax, rax), DEFINE_GPR_PSEUDO_32(ebx, rbx),
    DEFINE_GPR_PSEUDO_32(ecx, rcx), DEFINE_GPR_PSEUDO_32(edx, rdx),
    DEFINE_GPR_PSEUDO_32(edi, rdi), DEFINE_GPR_PSEUDO_32(esi, rsi),
    DEFINE_GPR_PSEUDO_32(ebp, rbp), DEFINE_GPR_PSEUDO_32(esp, rsp),
    DEFINE_GPR_PSEUDO_32(r8d, r8), DEFINE_GPR_PSEUDO_32(r9d, r9),
    DEFINE_GPR_PSEUDO_32(r10d, r10), DEFINE_GPR_PSEUDO_32(r11d, r11),
    DEFINE_GPR_PSEUDO_32(r12d, r12), DEFINE_GPR_PSEUDO_32(r13d, r13),
    DEFINE_GPR_PSEUDO_32(r14d, r14), DEFINE_GPR_PSEUDO_32(r15d, r15),
    DEFINE_GPR_PSEUDO_16(ax, rax), DEFINE_GPR_PSEUDO_16(bx, rbx),
    DEFINE_GPR_PSEUDO_16(cx, rcx), DEFINE_GPR_PSEUDO_16(dx, rdx),
    DEFINE_GPR_PSEUDO_16(di, rdi), DEFINE_GPR_PSEUDO_16(si, rsi),
    DEFINE_GPR_PSEUDO_16(bp, rbp), DEFINE_GPR_PSEUDO_16(sp, rsp),
    DEFINE_GPR_PSEUDO_16(r8w, r8), DEFINE_GPR_PSEUDO_16(r9w, r9),
    DEFINE_GPR_PSEUDO_16(r10w, r10), DEFINE_GPR_PSEUDO_16(r11w, r11),
    DEFINE_GPR_PSEUDO_16(r12w, r12), DEFINE_GPR_PSEUDO_16(r13w, r13),
    DEFINE_GPR_PSEUDO_16(r14w, r14), DEFINE_GPR_PSEUDO_16(r15w, r15),
    DEFINE_GPR_PSEUDO_8H(ah, rax), DEFINE_GPR_PSEUDO_8H(bh, rbx),
    DEFINE_GPR_PSEUDO_8H(ch, rcx), DEFINE_GPR_PSEUDO_8H(dh, rdx),
    DEFINE_GPR_PSEUDO_8L(al, rax), DEFINE_GPR_PSEUDO_8L(bl, rbx),
    DEFINE_GPR_PSEUDO_8L(cl, rcx), DEFINE_GPR_PSEUDO_8L(dl, rdx),
    DEFINE_GPR_PSEUDO_8L(dil, rdi), DEFINE_GPR_PSEUDO_8L(sil, rsi),
    DEFINE_GPR_PSEUDO_8L(bpl, rbp), DEFINE_GPR_PSEUDO_8L(spl, rsp),
    DEFINE_GPR_PSEUDO_8L(r8l, r8), DEFINE_GPR_PSEUDO_8L(r9l, r9),
    DEFINE_GPR_PSEUDO_8L(r10l, r10), DEFINE_GPR_PSEUDO_8L(r11l, r11),
    DEFINE_GPR_PSEUDO_8L(r12l, r12), DEFINE_GPR_PSEUDO_8L(r13l, r13),
    DEFINE_GPR_PSEUDO_8L(r14l, r14), DEFINE_GPR_PSEUDO_8L(r15l, r15),

//  i387 Floating point registers.         EH_frame             DWARF                Generic              Process Plugin       reg64
//  ====================================== ===============      ==================   ===================  ==================== =====
    DEFINE_FPR(fctrl,     fctrl,           dwarf_fctrl_x86_64,  dwarf_fctrl_x86_64,  LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR(fstat,     fstat,           dwarf_fstat_x86_64,  dwarf_fstat_x86_64,  LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR(ftag,      ftag,            LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR(fop,       fop,             LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR_32(fiseg,  ptr.i386_.fiseg, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, fip),
    DEFINE_FPR_32(fioff,  ptr.i386_.fioff, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, fip),
    DEFINE_FPR(fip,       ptr.x86_64.fip,  LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR_32(foseg,  ptr.i386_.foseg, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, fdp),
    DEFINE_FPR_32(fooff,  ptr.i386_.fooff, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, fdp),
    DEFINE_FPR(fdp,       ptr.x86_64.fdp,  LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR(mxcsr,     mxcsr,           dwarf_mxcsr_x86_64,  dwarf_mxcsr_x86_64,  LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),
    DEFINE_FPR(mxcsrmask, mxcsrmask,       LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM),

    // FP registers.
    DEFINE_FP_ST(st, 0), DEFINE_FP_ST(st, 1), DEFINE_FP_ST(st, 2),
    DEFINE_FP_ST(st, 3), DEFINE_FP_ST(st, 4), DEFINE_FP_ST(st, 5),
    DEFINE_FP_ST(st, 6), DEFINE_FP_ST(st, 7),

    DEFINE_FP_MM(mm, 0, st0), DEFINE_FP_MM(mm, 1, st1),
    DEFINE_FP_MM(mm, 2, st2), DEFINE_FP_MM(mm, 3, st3),
    DEFINE_FP_MM(mm, 4, st4), DEFINE_FP_MM(mm, 5, st5),
    DEFINE_FP_MM(mm, 6, st6), DEFINE_FP_MM(mm, 7, st7),

    // XMM registers
    DEFINE_XMM(xmm, 0), DEFINE_XMM(xmm, 1), DEFINE_XMM(xmm, 2),
    DEFINE_XMM(xmm, 3), DEFINE_XMM(xmm, 4), DEFINE_XMM(xmm, 5),
    DEFINE_XMM(xmm, 6), DEFINE_XMM(xmm, 7), DEFINE_XMM(xmm, 8),
    DEFINE_XMM(xmm, 9), DEFINE_XMM(xmm, 10), DEFINE_XMM(xmm, 11),
    DEFINE_XMM(xmm, 12), DEFINE_XMM(xmm, 13), DEFINE_XMM(xmm, 14),
    DEFINE_XMM(xmm, 15),

    // Copy of YMM registers assembled from xmm and ymmh
    DEFINE_YMM(ymm, 0), DEFINE_YMM(ymm, 1), DEFINE_YMM(ymm, 2),
    DEFINE_YMM(ymm, 3), DEFINE_YMM(ymm, 4), DEFINE_YMM(ymm, 5),
    DEFINE_YMM(ymm, 6), DEFINE_YMM(ymm, 7), DEFINE_YMM(ymm, 8),
    DEFINE_YMM(ymm, 9), DEFINE_YMM(ymm, 10), DEFINE_YMM(ymm, 11),
    DEFINE_YMM(ymm, 12), DEFINE_YMM(ymm, 13), DEFINE_YMM(ymm, 14),
    DEFINE_YMM(ymm, 15),

    // MPX registers
    DEFINE_BNDR(bnd, 0),
    DEFINE_BNDR(bnd, 1),
    DEFINE_BNDR(bnd, 2),
    DEFINE_BNDR(bnd, 3),

    DEFINE_BNDC(bndcfgu, 0),
    DEFINE_BNDC(bndstatus, 1),

    // Debug registers for lldb internal use
    DEFINE_DR(dr, 0), DEFINE_DR(dr, 1), DEFINE_DR(dr, 2), DEFINE_DR(dr, 3),
    DEFINE_DR(dr, 4), DEFINE_DR(dr, 5), DEFINE_DR(dr, 6), DEFINE_DR(dr, 7)};
#undef BNDC_OFFSET
#undef BNDC_SIZE
#undef BNDR_OFFSET
#undef BNDR_SIZE
#undef DEFINE_BNDC
#undef DEFINE_BNDR
#undef DEFINE_DR
#undef DEFINE_FPR
#undef DEFINE_FPR_32
#undef DEFINE_FP_MM
#undef DEFINE_FP_ST
#undef DEFINE_GPR
#undef DEFINE_GPR_PSEUDO_16
#undef DEFINE_GPR_PSEUDO_32
#undef DEFINE_GPR_PSEUDO_8H
#undef DEFINE_GPR_PSEUDO_8L
#undef DEFINE_XMM
#undef DEFINE_YMM
#undef DR_OFFSET
#undef DR_SIZE
#undef FPR_OFFSET
#undef FPR_SIZE
#undef FP_SIZE
#undef GPR_OFFSET
#undef XMM_SIZE
#undef YMM_OFFSET
#undef YMM_SIZE
