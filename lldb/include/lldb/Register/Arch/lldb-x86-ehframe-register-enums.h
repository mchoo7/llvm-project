//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_ARCH_LLDB_X86_EHFRAME_REGISTER_ENUMS_H
#define LLDB_REGISTER_ARCH_LLDB_X86_EHFRAME_REGISTER_ENUMS_H

// x86 keeps separate headers because LLDB's i386 DWARF and EH-frame
// mappings differ: ST0 is 11 in DWARF and 12 in EH-frame. The other
// architectures in this directory share a mapping for both register kinds.
// x86-64 also shares a mapping and uses the DWARF definitions for both.

namespace lldb_private {
// i386 EH-frame register numbers

// Register numbers seen in eh_frame (eRegisterKindEHFrame) on i386 systems
// (non-Darwin)
//
enum {
  ehframe_eax_i386 = 0,
  ehframe_ecx_i386,
  ehframe_edx_i386,
  ehframe_ebx_i386,

  // on Darwin esp & ebp are reversed in the eh_frame section for i386 (versus
  // dwarf's reg numbering).
  // To be specific:
  //    i386+darwin eh_frame:        4 is ebp, 5 is esp
  //    i386+everyone else eh_frame: 4 is esp, 5 is ebp
  //    i386 dwarf:                  4 is esp, 5 is ebp
  // lldb will get the darwin-specific eh_frame reg numberings from debugserver,
  // or the ABI, so we
  // only encode the generally correct 4 == esp, 5 == ebp numbers in this
  // generic header.

  ehframe_esp_i386,
  ehframe_ebp_i386,
  ehframe_esi_i386,
  ehframe_edi_i386,
  ehframe_eip_i386,
  ehframe_eflags_i386,
  ehframe_st0_i386 = 12,
  ehframe_st1_i386,
  ehframe_st2_i386,
  ehframe_st3_i386,
  ehframe_st4_i386,
  ehframe_st5_i386,
  ehframe_st6_i386,
  ehframe_st7_i386,
  ehframe_xmm0_i386 = 21,
  ehframe_xmm1_i386,
  ehframe_xmm2_i386,
  ehframe_xmm3_i386,
  ehframe_xmm4_i386,
  ehframe_xmm5_i386,
  ehframe_xmm6_i386,
  ehframe_xmm7_i386,
  ehframe_mm0_i386 = 29,
  ehframe_mm1_i386,
  ehframe_mm2_i386,
  ehframe_mm3_i386,
  ehframe_mm4_i386,
  ehframe_mm5_i386,
  ehframe_mm6_i386,
  ehframe_mm7_i386,
};

} // namespace lldb_private
#endif
