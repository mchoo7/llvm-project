//===-- NativeRegisterContextLinux_x86.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__i386__) || defined(__x86_64__)

#include "NativeRegisterContextLinux_x86.h"

#include "Plugins/Process/Linux/NativeProcessLinux.h"
#include "Plugins/Process/Linux/NativeThreadLinux.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_i386.h"
#include "lldb/Register/Layouts/Linux/RegisterModelLinux_x86_64.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include <algorithm>
#include <cstddef>
#include <optional>

// System includes - They have to be included after framework includes because
// they define some macros which collide with variable names in other modules.
#include <asm/ldt.h>
#include <cpuid.h>
#include <linux/elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 25
#endif

// Newer toolchains define __get_cpuid_count in cpuid.h, but some
// older-but-still-supported ones (e.g. gcc 5.4.0) don't, so we
// define it locally here, following the definition in clang/lib/Headers.
static inline int get_cpuid_count(unsigned int __leaf,
                                  unsigned int __subleaf,
                                  unsigned int *__eax, unsigned int *__ebx,
                                  unsigned int *__ecx, unsigned int *__edx)
{
  unsigned int __max_leaf = __get_cpuid_max(__leaf & 0x80000000, nullptr);

  if (__max_leaf == 0 || __max_leaf < __leaf)
    return 0;

  __cpuid_count(__leaf, __subleaf, *__eax, *__ebx, *__ecx, *__edx);
  return 1;
}

using namespace lldb_private;
using namespace lldb_private::process_linux;

// Linux exposes the i386 thread pointer as a synthetic register between the
// always-available FPU registers and the optional extended register sets.
constexpr uint32_t k_i386_thread_pointer_index = k_first_avx_i386;

// x86 32-bit general purpose registers.
static const uint32_t g_gpr_regnums_i386[] = {
    lldb_eax_i386,      lldb_ebx_i386,    lldb_ecx_i386, lldb_edx_i386,
    lldb_edi_i386,      lldb_esi_i386,    lldb_ebp_i386, lldb_esp_i386,
    lldb_eip_i386,      lldb_eflags_i386, lldb_cs_i386,  lldb_fs_i386,
    lldb_gs_i386,       lldb_ss_i386,     lldb_ds_i386,  lldb_es_i386,
    lldb_ax_i386,       lldb_bx_i386,     lldb_cx_i386,  lldb_dx_i386,
    lldb_di_i386,       lldb_si_i386,     lldb_bp_i386,  lldb_sp_i386,
    lldb_ah_i386,       lldb_bh_i386,     lldb_ch_i386,  lldb_dh_i386,
    lldb_al_i386,       lldb_bl_i386,     lldb_cl_i386,  lldb_dl_i386,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_gpr_regnums_i386) / sizeof(g_gpr_regnums_i386[0])) -
                      1 ==
                  k_num_gpr_registers_i386,
              "g_gpr_regnums_i386 has wrong number of register infos");

// x86 32-bit floating point registers.
static const uint32_t g_fpu_regnums_i386[] = {
    lldb_fctrl_i386,    lldb_fstat_i386,     lldb_ftag_i386,  lldb_fop_i386,
    lldb_fiseg_i386,    lldb_fioff_i386,     lldb_foseg_i386, lldb_fooff_i386,
    lldb_mxcsr_i386,    lldb_mxcsrmask_i386, lldb_st0_i386,   lldb_st1_i386,
    lldb_st2_i386,      lldb_st3_i386,       lldb_st4_i386,   lldb_st5_i386,
    lldb_st6_i386,      lldb_st7_i386,       lldb_mm0_i386,   lldb_mm1_i386,
    lldb_mm2_i386,      lldb_mm3_i386,       lldb_mm4_i386,   lldb_mm5_i386,
    lldb_mm6_i386,      lldb_mm7_i386,       lldb_xmm0_i386,  lldb_xmm1_i386,
    lldb_xmm2_i386,     lldb_xmm3_i386,      lldb_xmm4_i386,  lldb_xmm5_i386,
    lldb_xmm6_i386,     lldb_xmm7_i386,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_fpu_regnums_i386) / sizeof(g_fpu_regnums_i386[0])) -
                      1 ==
                  k_num_fpr_registers_i386,
              "g_fpu_regnums_i386 has wrong number of register infos");

// x86 32-bit AVX registers.
static const uint32_t g_avx_regnums_i386[] = {
    lldb_ymm0_i386,     lldb_ymm1_i386, lldb_ymm2_i386, lldb_ymm3_i386,
    lldb_ymm4_i386,     lldb_ymm5_i386, lldb_ymm6_i386, lldb_ymm7_i386,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_avx_regnums_i386) / sizeof(g_avx_regnums_i386[0])) -
                      1 ==
                  k_num_avx_registers_i386,
              " g_avx_regnums_i386 has wrong number of register infos");

// x64 32-bit MPX registers.
static const uint32_t g_mpx_regnums_i386[] = {
    lldb_bnd0_i386,     lldb_bnd1_i386, lldb_bnd2_i386, lldb_bnd3_i386,
    lldb_bndcfgu_i386,  lldb_bndstatus_i386,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_mpx_regnums_i386) / sizeof(g_mpx_regnums_i386[0])) -
                      1 ==
                  k_num_mpx_registers_i386,
              "g_mpx_regnums_x86_64 has wrong number of register infos");

// x86 64-bit general purpose registers.
static const uint32_t g_gpr_regnums_x86_64[] = {
    x86_64_with_base::lldb_rax,    x86_64_with_base::lldb_rbx,    x86_64_with_base::lldb_rcx, x86_64_with_base::lldb_rdx,
    x86_64_with_base::lldb_rdi,    x86_64_with_base::lldb_rsi,    x86_64_with_base::lldb_rbp, x86_64_with_base::lldb_rsp,
    x86_64_with_base::lldb_r8,     x86_64_with_base::lldb_r9,     x86_64_with_base::lldb_r10, x86_64_with_base::lldb_r11,
    x86_64_with_base::lldb_r12,    x86_64_with_base::lldb_r13,    x86_64_with_base::lldb_r14, x86_64_with_base::lldb_r15,
    x86_64_with_base::lldb_rip,    x86_64_with_base::lldb_rflags, x86_64_with_base::lldb_cs,  x86_64_with_base::lldb_fs,
    x86_64_with_base::lldb_gs,     x86_64_with_base::lldb_ss,     x86_64_with_base::lldb_fs_base, x86_64_with_base::lldb_gs_base,
    x86_64_with_base::lldb_ds,  x86_64_with_base::lldb_es,
    x86_64_with_base::lldb_eax,    x86_64_with_base::lldb_ebx,    x86_64_with_base::lldb_ecx, x86_64_with_base::lldb_edx,
    x86_64_with_base::lldb_edi,    x86_64_with_base::lldb_esi,    x86_64_with_base::lldb_ebp, x86_64_with_base::lldb_esp,
    x86_64_with_base::lldb_r8d,  // Low 32 bits or r8
    x86_64_with_base::lldb_r9d,  // Low 32 bits or r9
    x86_64_with_base::lldb_r10d, // Low 32 bits or r10
    x86_64_with_base::lldb_r11d, // Low 32 bits or r11
    x86_64_with_base::lldb_r12d, // Low 32 bits or r12
    x86_64_with_base::lldb_r13d, // Low 32 bits or r13
    x86_64_with_base::lldb_r14d, // Low 32 bits or r14
    x86_64_with_base::lldb_r15d, // Low 32 bits or r15
    x86_64_with_base::lldb_ax,     x86_64_with_base::lldb_bx,     x86_64_with_base::lldb_cx,  x86_64_with_base::lldb_dx,
    x86_64_with_base::lldb_di,     x86_64_with_base::lldb_si,     x86_64_with_base::lldb_bp,  x86_64_with_base::lldb_sp,
    x86_64_with_base::lldb_r8w,  // Low 16 bits or r8
    x86_64_with_base::lldb_r9w,  // Low 16 bits or r9
    x86_64_with_base::lldb_r10w, // Low 16 bits or r10
    x86_64_with_base::lldb_r11w, // Low 16 bits or r11
    x86_64_with_base::lldb_r12w, // Low 16 bits or r12
    x86_64_with_base::lldb_r13w, // Low 16 bits or r13
    x86_64_with_base::lldb_r14w, // Low 16 bits or r14
    x86_64_with_base::lldb_r15w, // Low 16 bits or r15
    x86_64_with_base::lldb_ah,     x86_64_with_base::lldb_bh,     x86_64_with_base::lldb_ch,  x86_64_with_base::lldb_dh,
    x86_64_with_base::lldb_al,     x86_64_with_base::lldb_bl,     x86_64_with_base::lldb_cl,  x86_64_with_base::lldb_dl,
    x86_64_with_base::lldb_dil,    x86_64_with_base::lldb_sil,    x86_64_with_base::lldb_bpl, x86_64_with_base::lldb_spl,
    x86_64_with_base::lldb_r8l,    // Low 8 bits or r8
    x86_64_with_base::lldb_r9l,    // Low 8 bits or r9
    x86_64_with_base::lldb_r10l,   // Low 8 bits or r10
    x86_64_with_base::lldb_r11l,   // Low 8 bits or r11
    x86_64_with_base::lldb_r12l,   // Low 8 bits or r12
    x86_64_with_base::lldb_r13l,   // Low 8 bits or r13
    x86_64_with_base::lldb_r14l,   // Low 8 bits or r14
    x86_64_with_base::lldb_r15l,   // Low 8 bits or r15
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_gpr_regnums_x86_64) / sizeof(g_gpr_regnums_x86_64[0])) -
                      1 ==
                  x86_64_with_base::k_num_gpr_registers,
              "g_gpr_regnums_x86_64 has wrong number of register infos");

// x86 64-bit floating point registers.
static const uint32_t g_fpu_regnums_x86_64[] = {
    x86_64_with_base::lldb_fctrl,  x86_64_with_base::lldb_fstat, x86_64_with_base::lldb_ftag,
    x86_64_with_base::lldb_fop,    x86_64_with_base::lldb_fiseg, x86_64_with_base::lldb_fioff,
    x86_64_with_base::lldb_fip,    x86_64_with_base::lldb_foseg, x86_64_with_base::lldb_fooff,
    x86_64_with_base::lldb_fdp,    x86_64_with_base::lldb_mxcsr, x86_64_with_base::lldb_mxcsrmask,
    x86_64_with_base::lldb_st0,    x86_64_with_base::lldb_st1,   x86_64_with_base::lldb_st2,
    x86_64_with_base::lldb_st3,    x86_64_with_base::lldb_st4,   x86_64_with_base::lldb_st5,
    x86_64_with_base::lldb_st6,    x86_64_with_base::lldb_st7,   x86_64_with_base::lldb_mm0,
    x86_64_with_base::lldb_mm1,    x86_64_with_base::lldb_mm2,   x86_64_with_base::lldb_mm3,
    x86_64_with_base::lldb_mm4,    x86_64_with_base::lldb_mm5,   x86_64_with_base::lldb_mm6,
    x86_64_with_base::lldb_mm7,    x86_64_with_base::lldb_xmm0,  x86_64_with_base::lldb_xmm1,
    x86_64_with_base::lldb_xmm2,   x86_64_with_base::lldb_xmm3,  x86_64_with_base::lldb_xmm4,
    x86_64_with_base::lldb_xmm5,   x86_64_with_base::lldb_xmm6,  x86_64_with_base::lldb_xmm7,
    x86_64_with_base::lldb_xmm8,   x86_64_with_base::lldb_xmm9,  x86_64_with_base::lldb_xmm10,
    x86_64_with_base::lldb_xmm11,  x86_64_with_base::lldb_xmm12, x86_64_with_base::lldb_xmm13,
    x86_64_with_base::lldb_xmm14,  x86_64_with_base::lldb_xmm15,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_fpu_regnums_x86_64) / sizeof(g_fpu_regnums_x86_64[0])) -
                      1 ==
                  x86_64_with_base::k_num_fpr_registers,
              "g_fpu_regnums_x86_64 has wrong number of register infos");

// x86 64-bit AVX registers.
static const uint32_t g_avx_regnums_x86_64[] = {
    x86_64_with_base::lldb_ymm0,   x86_64_with_base::lldb_ymm1,  x86_64_with_base::lldb_ymm2,  x86_64_with_base::lldb_ymm3,
    x86_64_with_base::lldb_ymm4,   x86_64_with_base::lldb_ymm5,  x86_64_with_base::lldb_ymm6,  x86_64_with_base::lldb_ymm7,
    x86_64_with_base::lldb_ymm8,   x86_64_with_base::lldb_ymm9,  x86_64_with_base::lldb_ymm10, x86_64_with_base::lldb_ymm11,
    x86_64_with_base::lldb_ymm12,  x86_64_with_base::lldb_ymm13, x86_64_with_base::lldb_ymm14, x86_64_with_base::lldb_ymm15,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_avx_regnums_x86_64) / sizeof(g_avx_regnums_x86_64[0])) -
                      1 ==
                  x86_64_with_base::k_num_avx_registers,
              "g_avx_regnums_x86_64 has wrong number of register infos");

// x86 64-bit MPX registers.
static const uint32_t g_mpx_regnums_x86_64[] = {
    x86_64_with_base::lldb_bnd0,    x86_64_with_base::lldb_bnd1,    x86_64_with_base::lldb_bnd2,
    x86_64_with_base::lldb_bnd3,    x86_64_with_base::lldb_bndcfgu, x86_64_with_base::lldb_bndstatus,
    LLDB_INVALID_REGNUM // register sets need to end with this flag
};
static_assert((sizeof(g_mpx_regnums_x86_64) / sizeof(g_mpx_regnums_x86_64[0])) -
                      1 ==
                  x86_64_with_base::k_num_mpx_registers,
              "g_mpx_regnums_x86_64 has wrong number of register infos");

// Number of register sets provided by this context.
constexpr unsigned k_num_extended_register_sets = 2, k_num_register_sets = 4;

// Register sets for x86 32-bit.
static const RegisterSet g_reg_sets_i386[k_num_register_sets] = {
    {"General Purpose Registers", "gpr", k_num_gpr_registers_i386,
     g_gpr_regnums_i386},
    {"Floating Point Registers", "fpu", k_num_fpr_registers_i386,
     g_fpu_regnums_i386},
    {"Advanced Vector Extensions", "avx", k_num_avx_registers_i386,
     g_avx_regnums_i386},
    { "Memory Protection Extensions", "mpx", k_num_mpx_registers_i386,
     g_mpx_regnums_i386}};

// Register sets for x86 64-bit.
static const RegisterSet g_reg_sets_x86_64[k_num_register_sets] = {
    {"General Purpose Registers", "gpr", x86_64_with_base::k_num_gpr_registers,
     g_gpr_regnums_x86_64},
    {"Floating Point Registers", "fpu", x86_64_with_base::k_num_fpr_registers,
     g_fpu_regnums_x86_64},
    {"Advanced Vector Extensions", "avx", x86_64_with_base::k_num_avx_registers,
     g_avx_regnums_x86_64},
    {"Memory Protection Extensions", "mpx",
     x86_64_with_base::k_num_mpx_registers, g_mpx_regnums_x86_64}};

#define REG_CONTEXT_SIZE (GetRegisterInfoProvider().GetGPRSize() + sizeof(FPR))

// Required ptrace defines.

// Support ptrace extensions even when compiled without required kernel support
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif
#ifndef NT_PRXFPREG
#define NT_PRXFPREG 0x46e62b7f
#endif

// On x86_64 NT_PRFPREG is used to access the FXSAVE area. On i386, we need to
// use NT_PRXFPREG.
static inline unsigned int fxsr_regset(const ArchSpec &arch) {
  return arch.GetAddressByteSize() == 8 ? NT_PRFPREG : NT_PRXFPREG;
}

// Required MPX define.

// Support MPX extensions also if compiled with compiler without MPX support.
#ifndef bit_MPX
#define bit_MPX 0x4000
#endif

// XCR0 extended register sets masks.
#define mask_XSTATE_AVX (1ULL << 2)
#define mask_XSTATE_BNDREGS (1ULL << 3)
#define mask_XSTATE_BNDCFG (1ULL << 4)
#define mask_XSTATE_MPX (mask_XSTATE_BNDREGS | mask_XSTATE_BNDCFG)

std::unique_ptr<NativeRegisterContextLinux>
NativeRegisterContextLinux::CreateHostNativeRegisterContextLinux(
    const ArchSpec &target_arch, NativeThreadLinux &native_thread) {
  return std::unique_ptr<NativeRegisterContextLinux>(
      new NativeRegisterContextLinux_x86(target_arch, native_thread));
}

llvm::Expected<ArchSpec>
NativeRegisterContextLinux::DetermineArchitecture(lldb::tid_t tid) {
  return DetermineArchitectureViaGPR(tid, sizeof(linux_x86_64::GPR));
}

// NativeRegisterContextLinux_x86 members.

static std::unique_ptr<RegisterInfo_x86>
CreateRegisterInfoInterface(const ArchSpec &target_arch) {
  if (HostInfo::GetArchitecture().GetAddressByteSize() == 4) {
    // 32-bit hosts use the i386 saved-state layout.
    return std::make_unique<RegisterInfo_x86>(
        target_arch, CreateLinuxI386RegisterModel(target_arch));
  } else {
    assert((HostInfo::GetArchitecture().GetAddressByteSize() == 8) &&
           "Register setting path assumes this is a 64-bit host");
    // X86_64 hosts know how to work with 64-bit and 32-bit EXEs using the
    // x86_64 register context.
    return std::make_unique<RegisterInfo_x86>(
        target_arch, CreateLinuxX86_64RegisterModel(target_arch));
  }
}

// Return the size of the XSTATE area supported on this cpu. It is necessary to
// allocate the full size of the area even if we do not use/recognise all of it
// because ptrace(PTRACE_SETREGSET, NT_X86_XSTATE) will refuse to write to it if
// we do not pass it a buffer of sufficient size. The size is always at least
// sizeof(FPR) so that the allocated buffer can be safely cast to FPR*.
static std::size_t GetXSTATESize() {
  unsigned int eax, ebx, ecx, edx;
  // First check whether the XSTATE are is supported at all.
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx) || !(ecx & bit_XSAVE))
    return sizeof(FPR);

  // Then fetch the maximum size of the area.
  if (!get_cpuid_count(0x0d, 0, &eax, &ebx, &ecx, &edx))
    return sizeof(FPR);
  return std::max<std::size_t>(ecx, sizeof(FPR));
}

NativeRegisterContextLinux_x86::NativeRegisterContextLinux_x86(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread)
    : NativeRegisterContextRegisterInfo(
          native_thread, CreateRegisterInfoInterface(target_arch).release()),
      NativeRegisterContextLinux(native_thread),
      m_xstate_type(XStateType::Invalid), m_reg_info(), m_gpr_x86_64() {
  const bool host64 = HostInfo::GetArchitecture().GetAddressByteSize() == 8;
  m_orig_ax_info = {
      host64 ? "orig_rax" : "orig_eax",
      nullptr,
      host64 ? 8u : 4u,
      static_cast<uint32_t>(host64 ? offsetof(linux_x86_64::GPR, orig_rax)
                                   : offsetof(linux_i386::GPR, orig_eax)),
      lldb::eEncodingUint,
      lldb::eFormatHex,
      {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,
       LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM},
      nullptr,
      nullptr,
      nullptr};
  // Set up data about ranges of valid registers.
  switch (target_arch.GetMachine()) {
  case llvm::Triple::x86: {
    m_i386_thread_pointer_info = {"gs_base",
                                  nullptr,
                                  sizeof(uint32_t),
                                  0,
                                  lldb::eEncodingUint,
                                  lldb::eFormatHex,
                                  {LLDB_INVALID_REGNUM, LLDB_INVALID_REGNUM,
                                   LLDB_REGNUM_GENERIC_TP, LLDB_INVALID_REGNUM,
                                   LLDB_INVALID_REGNUM},
                                  nullptr,
                                  nullptr,
                                  nullptr};

    m_reg_info.num_registers = k_num_registers_i386 + 1;
    m_reg_info.num_gpr_registers = k_num_gpr_registers_i386;
    m_reg_info.num_fpr_registers = k_num_fpr_registers_i386;
    m_reg_info.num_avx_registers = k_num_avx_registers_i386;
    m_reg_info.num_mpx_registers = k_num_mpx_registers_i386;
    m_reg_info.last_gpr = k_last_gpr_i386;
    m_reg_info.first_fpr = k_first_fpr_i386;
    m_reg_info.last_fpr = k_last_fpr_i386;
    m_reg_info.first_st = lldb_st0_i386;
    m_reg_info.last_st = lldb_st7_i386;
    m_reg_info.first_mm = lldb_mm0_i386;
    m_reg_info.last_mm = lldb_mm7_i386;
    m_reg_info.first_xmm = lldb_xmm0_i386;
    m_reg_info.last_xmm = lldb_xmm7_i386;
    m_reg_info.first_ymm = lldb_ymm0_i386;
    m_reg_info.last_ymm = lldb_ymm7_i386;
    m_reg_info.first_mpxr = lldb_bnd0_i386;
    m_reg_info.last_mpxr = lldb_bnd3_i386;
    m_reg_info.first_mpxc = lldb_bndcfgu_i386;
    m_reg_info.last_mpxc = lldb_bndstatus_i386;
    m_reg_info.first_dr = lldb_dr0_i386;
    m_reg_info.last_dr = lldb_dr7_i386;
    m_reg_info.gpr_flags = lldb_eflags_i386;
    break;
  }
  case llvm::Triple::x86_64:
    m_reg_info.num_registers = x86_64_with_base::k_num_registers;
    m_reg_info.num_gpr_registers = x86_64_with_base::k_num_gpr_registers;
    m_reg_info.num_fpr_registers = x86_64_with_base::k_num_fpr_registers;
    m_reg_info.num_avx_registers = x86_64_with_base::k_num_avx_registers;
    m_reg_info.num_mpx_registers = x86_64_with_base::k_num_mpx_registers;
    m_reg_info.last_gpr = x86_64_with_base::k_last_gpr;
    m_reg_info.first_fpr = x86_64_with_base::k_first_fpr;
    m_reg_info.last_fpr = x86_64_with_base::k_last_fpr;
    m_reg_info.first_st = x86_64_with_base::lldb_st0;
    m_reg_info.last_st = x86_64_with_base::lldb_st7;
    m_reg_info.first_mm = x86_64_with_base::lldb_mm0;
    m_reg_info.last_mm = x86_64_with_base::lldb_mm7;
    m_reg_info.first_xmm = x86_64_with_base::lldb_xmm0;
    m_reg_info.last_xmm = x86_64_with_base::lldb_xmm15;
    m_reg_info.first_ymm = x86_64_with_base::lldb_ymm0;
    m_reg_info.last_ymm = x86_64_with_base::lldb_ymm15;
    m_reg_info.first_mpxr = x86_64_with_base::lldb_bnd0;
    m_reg_info.last_mpxr = x86_64_with_base::lldb_bnd3;
    m_reg_info.first_mpxc = x86_64_with_base::lldb_bndcfgu;
    m_reg_info.last_mpxc = x86_64_with_base::lldb_bndstatus;
    m_reg_info.first_dr = x86_64_with_base::lldb_dr0;
    m_reg_info.last_dr = x86_64_with_base::lldb_dr7;
    m_reg_info.gpr_flags = x86_64_with_base::lldb_rflags;
    break;
  default:
    assert(false && "Unhandled target architecture.");
    break;
  }

  std::size_t xstate_size = GetXSTATESize();
  m_xstate.reset(static_cast<FPR *>(std::malloc(xstate_size)));
  m_iovec.iov_base = m_xstate.get();
  m_iovec.iov_len = xstate_size;

  // Clear out the FPR state.
  ::memset(m_xstate.get(), 0, xstate_size);
}

uint32_t NativeRegisterContextLinux_x86::GetRegisterCount() const {
  uint32_t count = NativeRegisterContextRegisterInfo::GetRegisterCount();
  if (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine() ==
      llvm::Triple::x86)
    ++count;
  return count;
}

const RegisterInfo *
NativeRegisterContextLinux_x86::GetRegisterInfoAtIndex(uint32_t reg) const {
  if (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine() ==
      llvm::Triple::x86) {
    if (reg == k_i386_thread_pointer_index)
      return &m_i386_thread_pointer_info;
    // Translate the public index back to the unchanged underlying table.
    if (reg > k_i386_thread_pointer_index)
      --reg;
  }
  return NativeRegisterContextRegisterInfo::GetRegisterInfoAtIndex(reg);
}

// CONSIDER after local and llgs debugging are merged, register set support can
// be moved into a base x86-64 class with IsRegisterSetAvailable made virtual.
uint32_t NativeRegisterContextLinux_x86::GetRegisterSetCount() const {
  uint32_t sets = 0;
  for (uint32_t set_index = 0; set_index < k_num_register_sets; ++set_index) {
    if (IsRegisterSetAvailable(set_index))
      ++sets;
  }

  return sets;
}

uint32_t NativeRegisterContextLinux_x86::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < k_num_register_sets; ++set_index) {
    const RegisterSet *set = GetRegisterSet(set_index);
    if (set)
      count += set->num_registers;
  }
  if (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine() ==
      llvm::Triple::x86)
    ++count;
  return count;
}

const RegisterSet *
NativeRegisterContextLinux_x86::GetRegisterSet(uint32_t set_index) const {
  if (!IsRegisterSetAvailable(set_index))
    return nullptr;

  switch (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::x86:
    return &g_reg_sets_i386[set_index];
  case llvm::Triple::x86_64:
    return &g_reg_sets_x86_64[set_index];
  default:
    assert(false && "Unhandled target architecture.");
    return nullptr;
  }

  return nullptr;
}

Status
NativeRegisterContextLinux_x86::ReadRegister(const RegisterInfo *reg_info,
                                             RegisterValue &reg_value) {
  if (!reg_info)
    return Status::FromErrorString("missing register description");
  if (IsThreadPointer(*reg_info))
    return ReadThreadPointer(reg_value);
  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];
  if (IsDR(reg))
    return ReadRegisterRaw(GetRegisterInfoIndex(reg), reg_value);
  const auto &provider = GetRegisterInfoProvider();
  auto required = provider.GetRegisterBanks(*reg_info, false);
  if (!required)
    return Status::FromError(required.takeError());
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case x86_layout::GP:
      status = ReadGPR();
      break;
    case x86_layout::FP:
      status = ReadFPR();
      break;
    case x86_layout::YMMHigh:
      status = ReadFPR();
      if (status.Success() && !IsCPUFeatureAvailable(RegSet::avx))
        return Status::FromErrorString("AVX state is unavailable");
      break;
    case x86_layout::Bounds:
    case x86_layout::BoundsControl:
      status = ReadFPR();
      if (status.Success() && !IsCPUFeatureAvailable(RegSet::mpx))
        return Status::FromErrorString("MPX state is unavailable");
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  if (llvm::StringRef(reg_info->name) == "ftag") {
    reg_value.SetUInt16(AbridgedToFullTagWord(
        m_xstate->fxsave.ftag, m_xstate->fxsave.fstat, m_xstate->fxsave.stmm));
    return Status();
  }
  auto value = provider.ReadRegister(
      *reg_info,
      {{x86_layout::GP,
        {reinterpret_cast<const uint8_t *>(&m_gpr_x86_64), GetGPRSize()}},
       {x86_layout::FP,
        {reinterpret_cast<const uint8_t *>(&m_xstate->fxsave), sizeof(FXSAVE)}},
       {x86_layout::YMMHigh,
        {reinterpret_cast<const uint8_t *>(&m_xstate->xsave.ymmh),
         sizeof(m_xstate->xsave.ymmh)}},
       {x86_layout::Bounds,
        {reinterpret_cast<const uint8_t *>(&m_xstate->xsave.mpxr),
         sizeof(m_xstate->xsave.mpxr)}},
       {x86_layout::BoundsControl,
        {reinterpret_cast<const uint8_t *>(&m_xstate->xsave.mpxc),
         sizeof(m_xstate->xsave.mpxc)}}});
  if (!value)
    return Status::FromError(value.takeError());
  reg_value = std::move(*value);
  return Status();
}

void NativeRegisterContextLinux_x86::UpdateXSTATEforWrite(uint32_t reg_index) {
  XSAVE_HDR::XFeature &xstate_bv = m_xstate->xsave.header.xstate_bv;
  if (IsFPR(reg_index)) {
    // IsFPR considers both %st and %xmm registers as floating point, but these
    // map to two features. Set both flags, just in case.
    xstate_bv |= XSAVE_HDR::XFeature::FP | XSAVE_HDR::XFeature::SSE;
  } else if (IsAVX(reg_index)) {
    // Lower bytes of some %ymm registers are shared with %xmm registers.
    xstate_bv |= XSAVE_HDR::XFeature::YMM | XSAVE_HDR::XFeature::SSE;
  } else if (IsMPX(reg_index)) {
    // MPX registers map to two XSAVE features.
    xstate_bv |= XSAVE_HDR::XFeature::BNDREGS | XSAVE_HDR::XFeature::BNDCSR;
  }
}

Status
NativeRegisterContextLinux_x86::WriteRegister(const RegisterInfo *reg_info,
                                              const RegisterValue &reg_value) {
  if (!reg_info)
    return Status::FromErrorString("missing register description");
  if (IsThreadPointer(*reg_info))
    return Status::FromErrorString("the i386 thread pointer is read-only");
  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];
  if (IsDR(reg))
    return WriteRegisterRaw(GetRegisterInfoIndex(reg), reg_value);
  const auto &provider = GetRegisterInfoProvider();
  auto required = provider.GetRegisterBanks(*reg_info, true);
  if (!required)
    return Status::FromError(required.takeError());
  bool write_gp = false, write_fp = false;
  for (RegisterBankID bank : *required) {
    Status status;
    switch (bank) {
    case x86_layout::GP:
      status = ReadGPR();
      write_gp = true;
      break;
    case x86_layout::FP:
      status = ReadFPR();
      write_fp = true;
      break;
    case x86_layout::YMMHigh:
      status = ReadFPR();
      write_fp = true;
      if (status.Success() && !IsCPUFeatureAvailable(RegSet::avx))
        return Status::FromErrorString("AVX state is unavailable");
      break;
    case x86_layout::Bounds:
    case x86_layout::BoundsControl:
      status = ReadFPR();
      write_fp = true;
      if (status.Success() && !IsCPUFeatureAvailable(RegSet::mpx))
        return Status::FromErrorString("MPX state is unavailable");
      break;
    default:
      return Status::FromErrorString("unsupported register bank");
    }
    if (status.Fail())
      return status;
  }
  if (llvm::StringRef(reg_info->name) == "ftag")
    m_xstate->fxsave.ftag = FullToAbridgedTagWord(reg_value.GetAsUInt16());
  else if (auto error = provider.WriteRegister(
               *reg_info, reg_value,
               {{x86_layout::GP,
                 {reinterpret_cast<uint8_t *>(&m_gpr_x86_64), GetGPRSize()}},
                {x86_layout::FP,
                 {reinterpret_cast<uint8_t *>(&m_xstate->fxsave),
                  sizeof(FXSAVE)}},
                {x86_layout::YMMHigh,
                 {reinterpret_cast<uint8_t *>(&m_xstate->xsave.ymmh),
                  sizeof(m_xstate->xsave.ymmh)}},
                {x86_layout::Bounds,
                 {reinterpret_cast<uint8_t *>(&m_xstate->xsave.mpxr),
                  sizeof(m_xstate->xsave.mpxr)}},
                {x86_layout::BoundsControl,
                 {reinterpret_cast<uint8_t *>(&m_xstate->xsave.mpxc),
                  sizeof(m_xstate->xsave.mpxc)}}}))
    return Status::FromError(std::move(error));
  if (write_gp) {
    Status status = WriteGPR();
    if (status.Fail())
      return status;
  }
  if (write_fp) {
    UpdateXSTATEforWrite(reg);
    return WriteFPR();
  }
  return Status();
}

Status NativeRegisterContextLinux_x86::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error;

  data_sp.reset(new DataBufferHeap(REG_CONTEXT_SIZE, 0));
  error = ReadGPR();
  if (error.Fail())
    return error;

  error = ReadFPR();
  if (error.Fail())
    return error;

  uint8_t *dst = data_sp->GetBytes();
  ::memcpy(dst, &m_gpr_x86_64, GetRegisterInfoProvider().GetGPRSize());
  dst += GetRegisterInfoProvider().GetGPRSize();
  if (m_xstate_type == XStateType::FXSAVE)
    ::memcpy(dst, &m_xstate->fxsave, sizeof(m_xstate->fxsave));
  else if (m_xstate_type == XStateType::XSAVE) {
    ::memcpy(dst, m_xstate.get(), sizeof(FPR));
  } else {
    assert(false && "how do we save the floating point registers?");
    error = Status::FromErrorString(
        "unsure how to save the floating point registers");
  }
  /** The following code is specific to Linux x86 based architectures,
   *  where the register orig_eax (32 bit)/orig_rax (64 bit) is set to
   *  -1 to solve the bug 23659, such a setting prevents the automatic
   *  decrement of the instruction pointer which was causing the SIGILL
   *  exception.
   * **/

  RegisterValue value((uint64_t)-1);
  const RegisterInfo &info = m_orig_ax_info;
  return DoWriteRegisterValue(info.byte_offset, info.name, value);

  return error;
}

Status NativeRegisterContextLinux_x86::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_x86::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != REG_CONTEXT_SIZE) {
    error = Status::FromErrorStringWithFormatv(
        "data_sp contained mismatched data size, expected {0}, actual {1}",
        REG_CONTEXT_SIZE, data_sp->GetByteSize());
    return error;
  }

  const uint8_t *src = data_sp->GetBytes();
  if (src == nullptr) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_x86::%s "
        "DataBuffer::GetBytes() returned a null "
        "pointer",
        __FUNCTION__);
    return error;
  }
  ::memcpy(&m_gpr_x86_64, src, GetRegisterInfoProvider().GetGPRSize());

  error = WriteGPR();
  if (error.Fail())
    return error;

  src += GetRegisterInfoProvider().GetGPRSize();
  if (m_xstate_type == XStateType::FXSAVE)
    ::memcpy(&m_xstate->fxsave, src, sizeof(m_xstate->fxsave));
  else if (m_xstate_type == XStateType::XSAVE)
    ::memcpy(&m_xstate->xsave, src, sizeof(m_xstate->xsave));

  error = WriteFPR();
  if (error.Fail())
    return error;

  return error;
}

bool NativeRegisterContextLinux_x86::IsCPUFeatureAvailable(
    RegSet feature_code) const {
  if (m_xstate_type == XStateType::Invalid) {
    if (const_cast<NativeRegisterContextLinux_x86 *>(this)->ReadFPR().Fail())
      return false;
  }
  switch (feature_code) {
  case RegSet::gpr:
  case RegSet::fpu:
    return true;
  case RegSet::avx: // Check if CPU has AVX and if there is kernel support, by
                    // reading in the XCR0 area of XSAVE.
    if ((m_xstate->xsave.i387.xcr0 & mask_XSTATE_AVX) == mask_XSTATE_AVX)
      return true;
     break;
  case RegSet::mpx: // Check if CPU has MPX and if there is kernel support, by
                    // reading in the XCR0 area of XSAVE.
    if ((m_xstate->xsave.i387.xcr0 & mask_XSTATE_MPX) == mask_XSTATE_MPX)
      return true;
    break;
  }
  return false;
}

bool NativeRegisterContextLinux_x86::IsRegisterSetAvailable(
    uint32_t set_index) const {
  uint32_t num_sets = k_num_register_sets - k_num_extended_register_sets;

  switch (static_cast<RegSet>(set_index)) {
  case RegSet::gpr:
  case RegSet::fpu:
    return (set_index < num_sets);
  case RegSet::avx:
    return IsCPUFeatureAvailable(RegSet::avx);
  case RegSet::mpx:
    return IsCPUFeatureAvailable(RegSet::mpx);
  }
  return false;
}

bool NativeRegisterContextLinux_x86::IsGPR(uint32_t reg_index) const {
  // GPRs come first.
  return reg_index <= m_reg_info.last_gpr;
}

bool NativeRegisterContextLinux_x86::IsFPR(uint32_t reg_index) const {
  return (m_reg_info.first_fpr <= reg_index &&
          reg_index <= m_reg_info.last_fpr);
}

bool NativeRegisterContextLinux_x86::IsDR(uint32_t reg_index) const {
  return (m_reg_info.first_dr <= reg_index &&
          reg_index <= m_reg_info.last_dr);
}

Status NativeRegisterContextLinux_x86::WriteFPR() {
  switch (m_xstate_type) {
  case XStateType::FXSAVE:
    return WriteRegisterSet(
        &m_iovec, sizeof(m_xstate->fxsave),
        fxsr_regset(GetRegisterInfoProvider().GetTargetArchitecture()));
  case XStateType::XSAVE:
    return WriteRegisterSet(&m_iovec, sizeof(m_xstate->xsave), NT_X86_XSTATE);
  default:
    return Status::FromErrorString("Unrecognized FPR type.");
  }
}

bool NativeRegisterContextLinux_x86::IsAVX(uint32_t reg_index) const {
  if (!IsCPUFeatureAvailable(RegSet::avx))
    return false;
  return (m_reg_info.first_ymm <= reg_index &&
          reg_index <= m_reg_info.last_ymm);
}

void *NativeRegisterContextLinux_x86::GetFPRBuffer() {
  switch (m_xstate_type) {
  case XStateType::FXSAVE:
    return &m_xstate->fxsave;
  case XStateType::XSAVE:
    return &m_iovec;
  default:
    return nullptr;
  }
}

size_t NativeRegisterContextLinux_x86::GetFPRSize() {
  switch (m_xstate_type) {
  case XStateType::FXSAVE:
    return sizeof(m_xstate->fxsave);
  case XStateType::XSAVE:
    return sizeof(m_iovec);
  default:
    return 0;
  }
}

Status NativeRegisterContextLinux_x86::ReadFPR() {
  Status error;

  // Probe XSAVE and if it is not supported fall back to FXSAVE.
  if (m_xstate_type != XStateType::FXSAVE) {
    error = ReadRegisterSet(&m_iovec, sizeof(m_xstate->xsave), NT_X86_XSTATE);
    if (!error.Fail()) {
      m_xstate_type = XStateType::XSAVE;
      return error;
    }
  }
  error = ReadRegisterSet(
      &m_iovec, sizeof(m_xstate->xsave),
      fxsr_regset(GetRegisterInfoProvider().GetTargetArchitecture()));
  if (!error.Fail()) {
    m_xstate_type = XStateType::FXSAVE;
    return error;
  }
  return Status::FromErrorString("Unrecognized FPR type.");
}

bool NativeRegisterContextLinux_x86::IsMPX(uint32_t reg_index) const {
  if (!IsCPUFeatureAvailable(RegSet::mpx))
    return false;
  return (m_reg_info.first_mpxr <= reg_index &&
          reg_index <= m_reg_info.last_mpxc);
}

bool NativeRegisterContextLinux_x86::IsThreadPointer(
    const RegisterInfo &reg_info) const {
  return GetRegisterInfoProvider().GetTargetArchitecture().GetMachine() ==
             llvm::Triple::x86 &&
         reg_info.kinds[lldb::eRegisterKindGeneric] == LLDB_REGNUM_GENERIC_TP;
}

Status
NativeRegisterContextLinux_x86::ReadThreadPointer(RegisterValue &reg_value) {
  RegisterValue selector;
  Status error = ReadRegisterRaw(lldb_gs_i386, selector);
  if (error.Fail())
    return error;

  const uint32_t gs = selector.GetAsUInt32();
  // Selectors 0 through 3 refer to the null GDT descriptor with different
  // requested privilege levels.
  if (gs < 4) {
    reg_value.SetUInt32(0);
    return Status();
  }
  if (gs & 4)
    return Status::FromErrorString(
        "cannot read the i386 thread pointer from an LDT selector");

  const uintptr_t entry_number = gs >> 3;
  user_desc descriptor = {};
  error = NativeProcessLinux::PtraceWrapper(
      PTRACE_GET_THREAD_AREA, m_thread.GetID(),
      reinterpret_cast<void *>(entry_number), &descriptor, sizeof(descriptor));
  if (error.Fail())
    return error;

  reg_value.SetUInt32(descriptor.base_addr);
  return Status();
}

uint32_t
NativeRegisterContextLinux_x86::GetRegisterInfoIndex(uint32_t lldb_reg) const {
  // Raw register helpers take register-info indices rather than LLDB numbers.
  if (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine() ==
          llvm::Triple::x86 &&
      lldb_reg >= k_i386_thread_pointer_index)
    return lldb_reg + 1;
  return lldb_reg;
}

uint32_t NativeRegisterContextLinux_x86::GetPtraceOffset(uint32_t reg_index) {
  const auto *info = GetRegisterInfoAtIndex(reg_index);
  const auto &provider = GetRegisterInfoProvider();
  const auto *reg = provider.GetDescription().Find(info->name);
  const auto *location = provider.GetLayout().Find(reg->id);
  assert(location && location->pieces.size() == 1);
  const auto &piece = location->pieces.front();
  if (piece.bank == x86_layout::Debug) {
    // PEEKUSER/POKEUSER offsets are native ABI details, not packet offsets.
#if defined(__x86_64__)
    return offsetof(struct user, u_debugreg) + piece.byte_offset;
#else
    return 0xfc + piece.byte_offset;
#endif
  }
  assert(piece.bank == x86_layout::GP);
  return piece.byte_offset;
}

std::optional<NativeRegisterContextLinux::SyscallData>
NativeRegisterContextLinux_x86::GetSyscallData() {
  switch (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::x86: {
    static const uint8_t Int80[] = {0xcd, 0x80};
    static const uint32_t Args[] = {lldb_eax_i386, lldb_ebx_i386, lldb_ecx_i386,
                                    lldb_edx_i386, lldb_esi_i386, lldb_edi_i386,
                                    lldb_ebp_i386};
    return SyscallData{Int80, Args, lldb_eax_i386};
  }
  case llvm::Triple::x86_64: {
    static const uint8_t Syscall[] = {0x0f, 0x05};
    static const uint32_t Args[] = {
        x86_64_with_base::lldb_rax, x86_64_with_base::lldb_rdi, x86_64_with_base::lldb_rsi, x86_64_with_base::lldb_rdx,
        x86_64_with_base::lldb_r10, x86_64_with_base::lldb_r8,  x86_64_with_base::lldb_r9};
    return SyscallData{Syscall, Args, x86_64_with_base::lldb_rax};
  }
  default:
    llvm_unreachable("Unhandled architecture!");
  }
}

std::optional<NativeRegisterContextLinux::MmapData>
NativeRegisterContextLinux_x86::GetMmapData() {
  switch (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::x86:
    return MmapData{192, 91};
  case llvm::Triple::x86_64:
    return MmapData{9, 11};
  default:
    llvm_unreachable("Unhandled architecture!");
  }
}

const RegisterInfo *NativeRegisterContextLinux_x86::GetDR(int num) const {
  assert(num >= 0 && num <= 7);
  switch (GetRegisterInfoProvider().GetTargetArchitecture().GetMachine()) {
  case llvm::Triple::x86:
    return GetRegisterInfoAtIndex(GetRegisterInfoIndex(lldb_dr0_i386 + num));
  case llvm::Triple::x86_64:
    return GetRegisterInfoAtIndex(x86_64_with_base::lldb_dr0 + num);
  default:
    llvm_unreachable("Unhandled target architecture.");
  }
}

#endif // defined(__i386__) || defined(__x86_64__)
