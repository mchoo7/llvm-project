//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_ARCH_LLDB_X86_DWARF_REGISTER_ENUMS_H
#define LLDB_REGISTER_ARCH_LLDB_X86_DWARF_REGISTER_ENUMS_H

// x86 keeps separate headers because LLDB's i386 DWARF and EH-frame
// mappings differ: ST0 is 11 in DWARF and 12 in EH-frame. The other
// architectures in this directory share a mapping for both register kinds.
// x86-64 also shares a mapping and uses the DWARF definitions for both.

namespace lldb_private {
// DWARF register numbers (eRegisterKindDWARF)
// Intel's x86 or IA-32
enum {
  // General Purpose Registers.
  dwarf_eax_i386 = 0,
  dwarf_ecx_i386,
  dwarf_edx_i386,
  dwarf_ebx_i386,
  dwarf_esp_i386,
  dwarf_ebp_i386,
  dwarf_esi_i386,
  dwarf_edi_i386,
  dwarf_eip_i386,
  dwarf_eflags_i386,
  // Floating Point Registers
  dwarf_st0_i386 = 11,
  dwarf_st1_i386,
  dwarf_st2_i386,
  dwarf_st3_i386,
  dwarf_st4_i386,
  dwarf_st5_i386,
  dwarf_st6_i386,
  dwarf_st7_i386,
  // SSE Registers
  dwarf_xmm0_i386 = 21,
  dwarf_xmm1_i386,
  dwarf_xmm2_i386,
  dwarf_xmm3_i386,
  dwarf_xmm4_i386,
  dwarf_xmm5_i386,
  dwarf_xmm6_i386,
  dwarf_xmm7_i386,
  // MMX Registers
  dwarf_mm0_i386 = 29,
  dwarf_mm1_i386,
  dwarf_mm2_i386,
  dwarf_mm3_i386,
  dwarf_mm4_i386,
  dwarf_mm5_i386,
  dwarf_mm6_i386,
  dwarf_mm7_i386,
  dwarf_fctrl_i386 = 37, // x87 control word
  dwarf_fstat_i386 = 38, // x87 status word
  dwarf_mxcsr_i386 = 39,
  dwarf_es_i386 = 40,
  dwarf_cs_i386 = 41,
  dwarf_ss_i386 = 42,
  dwarf_ds_i386 = 43,
  dwarf_fs_i386 = 44,
  dwarf_gs_i386 = 45,

  // I believe the ymm registers use the dwarf_xmm%_i386 register numbers and
  //  then differentiate based on size of the register.
  dwarf_bnd0_i386 = 101,
  dwarf_bnd1_i386,
  dwarf_bnd2_i386,
  dwarf_bnd3_i386,
};

// AMD x86_64, AMD64, Intel EM64T, or Intel 64 ehframe, dwarf regnums

// EHFrame and DWARF Register numbers (eRegisterKindEHFrame &
// eRegisterKindDWARF)
//  This is the spec I used (as opposed to x86-64-abi-0.99.pdf):
//  http://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf
enum {
  // GP Registers
  dwarf_rax_x86_64 = 0,
  dwarf_rdx_x86_64,
  dwarf_rcx_x86_64,
  dwarf_rbx_x86_64,
  dwarf_rsi_x86_64,
  dwarf_rdi_x86_64,
  dwarf_rbp_x86_64,
  dwarf_rsp_x86_64,
  // Extended GP Registers
  dwarf_r8_x86_64 = 8,
  dwarf_r9_x86_64,
  dwarf_r10_x86_64,
  dwarf_r11_x86_64,
  dwarf_r12_x86_64,
  dwarf_r13_x86_64,
  dwarf_r14_x86_64,
  dwarf_r15_x86_64,
  // Return Address (RA) mapped to RIP
  dwarf_rip_x86_64 = 16,
  // SSE Vector Registers
  dwarf_xmm0_x86_64 = 17,
  dwarf_xmm1_x86_64,
  dwarf_xmm2_x86_64,
  dwarf_xmm3_x86_64,
  dwarf_xmm4_x86_64,
  dwarf_xmm5_x86_64,
  dwarf_xmm6_x86_64,
  dwarf_xmm7_x86_64,
  dwarf_xmm8_x86_64,
  dwarf_xmm9_x86_64,
  dwarf_xmm10_x86_64,
  dwarf_xmm11_x86_64,
  dwarf_xmm12_x86_64,
  dwarf_xmm13_x86_64,
  dwarf_xmm14_x86_64,
  dwarf_xmm15_x86_64,
  // Floating Point Registers
  dwarf_st0_x86_64 = 33,
  dwarf_st1_x86_64,
  dwarf_st2_x86_64,
  dwarf_st3_x86_64,
  dwarf_st4_x86_64,
  dwarf_st5_x86_64,
  dwarf_st6_x86_64,
  dwarf_st7_x86_64,
  // MMX Registers
  dwarf_mm0_x86_64 = 41,
  dwarf_mm1_x86_64,
  dwarf_mm2_x86_64,
  dwarf_mm3_x86_64,
  dwarf_mm4_x86_64,
  dwarf_mm5_x86_64,
  dwarf_mm6_x86_64,
  dwarf_mm7_x86_64,
  // Control and Status Flags Register
  dwarf_rflags_x86_64 = 49,
  //  selector registers
  dwarf_es_x86_64 = 50,
  dwarf_cs_x86_64,
  dwarf_ss_x86_64,
  dwarf_ds_x86_64,
  dwarf_fs_x86_64,
  dwarf_gs_x86_64,
  // Base registers
  dwarf_fs_base_x86_64 = 58,
  dwarf_gs_base_x86_64 = 59,
  // Floating point control registers
  dwarf_mxcsr_x86_64 = 64, // Media Control and Status
  dwarf_fctrl_x86_64,      // x87 control word
  dwarf_fstat_x86_64,      // x87 status word
  // Upper Vector Registers
  dwarf_ymm0h_x86_64 = 67,
  dwarf_ymm1h_x86_64,
  dwarf_ymm2h_x86_64,
  dwarf_ymm3h_x86_64,
  dwarf_ymm4h_x86_64,
  dwarf_ymm5h_x86_64,
  dwarf_ymm6h_x86_64,
  dwarf_ymm7h_x86_64,
  dwarf_ymm8h_x86_64,
  dwarf_ymm9h_x86_64,
  dwarf_ymm10h_x86_64,
  dwarf_ymm11h_x86_64,
  dwarf_ymm12h_x86_64,
  dwarf_ymm13h_x86_64,
  dwarf_ymm14h_x86_64,
  dwarf_ymm15h_x86_64,
  // MPX registers
  dwarf_bnd0_x86_64 = 126,
  dwarf_bnd1_x86_64,
  dwarf_bnd2_x86_64,
  dwarf_bnd3_x86_64,
  // AVX2 Vector Mask Registers
  // dwarf_k0_x86_64 = 118,
  // dwarf_k1_x86_64,
  // dwarf_k2_x86_64,
  // dwarf_k3_x86_64,
  // dwarf_k4_x86_64,
  // dwarf_k5_x86_64,
  // dwarf_k6_x86_64,
  // dwarf_k7_x86_64,
};

} // namespace lldb_private

#endif // LLDB_REGISTER_ARCH_LLDB_X86_DWARF_REGISTER_ENUMS_H
