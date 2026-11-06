//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_x86.h"
#include "lldb/Register/Arch/lldb-x86-dwarf-register-enums.h"
#include "lldb/Register/Arch/lldb-x86-ehframe-register-enums.h"
#include "lldb/lldb-private-types.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/ErrorHandling.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <mutex>
#include <set>

using namespace lldb_private;
using namespace lldb;
namespace {
namespace x86_register_info {
static uint32_t g_contained_eax[] = {lldb_eax_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_ebx[] = {lldb_ebx_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_ecx[] = {lldb_ecx_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_edx[] = {lldb_edx_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_edi[] = {lldb_edi_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_esi[] = {lldb_esi_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_ebp[] = {lldb_ebp_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_esp[] = {lldb_esp_i386, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_eax[] = {lldb_eax_i386, lldb_ax_i386, lldb_ah_i386,
                                      lldb_al_i386, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_ebx[] = {lldb_ebx_i386, lldb_bx_i386, lldb_bh_i386,
                                      lldb_bl_i386, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_ecx[] = {lldb_ecx_i386, lldb_cx_i386, lldb_ch_i386,
                                      lldb_cl_i386, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_edx[] = {lldb_edx_i386, lldb_dx_i386, lldb_dh_i386,
                                      lldb_dl_i386, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_edi[] = {lldb_edi_i386, lldb_di_i386,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_esi[] = {lldb_esi_i386, lldb_si_i386,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_ebp[] = {lldb_ebp_i386, lldb_bp_i386,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_esp[] = {lldb_esp_i386, lldb_sp_i386,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_contained_rax[] = {lldb_rax_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rbx[] = {lldb_rbx_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rcx[] = {lldb_rcx_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rdx[] = {lldb_rdx_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rdi[] = {lldb_rdi_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rsi[] = {lldb_rsi_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rbp[] = {lldb_rbp_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_rsp[] = {lldb_rsp_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r8[] = {lldb_r8_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r9[] = {lldb_r9_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r10[] = {lldb_r10_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r11[] = {lldb_r11_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r12[] = {lldb_r12_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r13[] = {lldb_r13_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r14[] = {lldb_r14_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_r15[] = {lldb_r15_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rax[] = {lldb_rax_x86_64, lldb_eax_x86_64,
                                      lldb_ax_x86_64,  lldb_ah_x86_64,
                                      lldb_al_x86_64,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rbx[] = {lldb_rbx_x86_64, lldb_ebx_x86_64,
                                      lldb_bx_x86_64,  lldb_bh_x86_64,
                                      lldb_bl_x86_64,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rcx[] = {lldb_rcx_x86_64, lldb_ecx_x86_64,
                                      lldb_cx_x86_64,  lldb_ch_x86_64,
                                      lldb_cl_x86_64,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rdx[] = {lldb_rdx_x86_64, lldb_edx_x86_64,
                                      lldb_dx_x86_64,  lldb_dh_x86_64,
                                      lldb_dl_x86_64,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rdi[] = {lldb_rdi_x86_64, lldb_edi_x86_64,
                                      lldb_di_x86_64, lldb_dil_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rsi[] = {lldb_rsi_x86_64, lldb_esi_x86_64,
                                      lldb_si_x86_64, lldb_sil_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rbp[] = {lldb_rbp_x86_64, lldb_ebp_x86_64,
                                      lldb_bp_x86_64, lldb_bpl_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rsp[] = {lldb_rsp_x86_64, lldb_esp_x86_64,
                                      lldb_sp_x86_64, lldb_spl_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r8[] = {lldb_r8_x86_64, lldb_r8d_x86_64,
                                     lldb_r8w_x86_64, lldb_r8l_x86_64,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r9[] = {lldb_r9_x86_64, lldb_r9d_x86_64,
                                     lldb_r9w_x86_64, lldb_r9l_x86_64,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r10[] = {lldb_r10_x86_64, lldb_r10d_x86_64,
                                      lldb_r10w_x86_64, lldb_r10l_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r11[] = {lldb_r11_x86_64, lldb_r11d_x86_64,
                                      lldb_r11w_x86_64, lldb_r11l_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r12[] = {lldb_r12_x86_64, lldb_r12d_x86_64,
                                      lldb_r12w_x86_64, lldb_r12l_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r13[] = {lldb_r13_x86_64, lldb_r13d_x86_64,
                                      lldb_r13w_x86_64, lldb_r13l_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r14[] = {lldb_r14_x86_64, lldb_r14d_x86_64,
                                      lldb_r14w_x86_64, lldb_r14l_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r15[] = {lldb_r15_x86_64, lldb_r15d_x86_64,
                                      lldb_r15w_x86_64, lldb_r15l_x86_64,
                                      LLDB_INVALID_REGNUM};
static uint32_t g_contained_fip[] = {lldb_fip_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_fdp[] = {lldb_fdp_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_fip[] = {lldb_fip_x86_64, lldb_fioff_x86_64,
                                      lldb_fiseg_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_fdp[] = {lldb_fdp_x86_64, lldb_fooff_x86_64,
                                      lldb_foseg_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st0_32[] = {lldb_st0_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st1_32[] = {lldb_st1_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st2_32[] = {lldb_st2_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st3_32[] = {lldb_st3_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st4_32[] = {lldb_st4_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st5_32[] = {lldb_st5_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st6_32[] = {lldb_st6_i386, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st7_32[] = {lldb_st7_i386, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st0_32[] = {lldb_st0_i386, lldb_mm0_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st1_32[] = {lldb_st1_i386, lldb_mm1_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st2_32[] = {lldb_st2_i386, lldb_mm2_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st3_32[] = {lldb_st3_i386, lldb_mm3_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st4_32[] = {lldb_st4_i386, lldb_mm4_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st5_32[] = {lldb_st5_i386, lldb_mm5_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st6_32[] = {lldb_st6_i386, lldb_mm6_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st7_32[] = {lldb_st7_i386, lldb_mm7_i386,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_contained_st0_64[] = {lldb_st0_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st1_64[] = {lldb_st1_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st2_64[] = {lldb_st2_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st3_64[] = {lldb_st3_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st4_64[] = {lldb_st4_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st5_64[] = {lldb_st5_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st6_64[] = {lldb_st6_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st7_64[] = {lldb_st7_x86_64, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st0_64[] = {lldb_st0_x86_64, lldb_mm0_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st1_64[] = {lldb_st1_x86_64, lldb_mm1_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st2_64[] = {lldb_st2_x86_64, lldb_mm2_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st3_64[] = {lldb_st3_x86_64, lldb_mm3_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st4_64[] = {lldb_st4_x86_64, lldb_mm4_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st5_64[] = {lldb_st5_x86_64, lldb_mm5_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st6_64[] = {lldb_st6_x86_64, lldb_mm6_x86_64,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st7_64[] = {lldb_st7_x86_64, lldb_mm7_x86_64,
                                         LLDB_INVALID_REGNUM};
} // namespace x86_register_info
namespace RegisterInfos_x86_64_with_base_shared {
static uint32_t g_contained_rax[] = {x86_64_with_base::lldb_rax,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rbx[] = {x86_64_with_base::lldb_rbx,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rcx[] = {x86_64_with_base::lldb_rcx,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rdx[] = {x86_64_with_base::lldb_rdx,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rdi[] = {x86_64_with_base::lldb_rdi,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rsi[] = {x86_64_with_base::lldb_rsi,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rbp[] = {x86_64_with_base::lldb_rbp,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_rsp[] = {x86_64_with_base::lldb_rsp,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_r8[] = {x86_64_with_base::lldb_r8,
                                    LLDB_INVALID_REGNUM};
static uint32_t g_contained_r9[] = {x86_64_with_base::lldb_r9,
                                    LLDB_INVALID_REGNUM};
static uint32_t g_contained_r10[] = {x86_64_with_base::lldb_r10,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_r11[] = {x86_64_with_base::lldb_r11,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_r12[] = {x86_64_with_base::lldb_r12,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_r13[] = {x86_64_with_base::lldb_r13,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_r14[] = {x86_64_with_base::lldb_r14,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_r15[] = {x86_64_with_base::lldb_r15,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rax[] = {
    x86_64_with_base::lldb_rax, x86_64_with_base::lldb_eax,
    x86_64_with_base::lldb_ax,  x86_64_with_base::lldb_ah,
    x86_64_with_base::lldb_al,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rbx[] = {
    x86_64_with_base::lldb_rbx, x86_64_with_base::lldb_ebx,
    x86_64_with_base::lldb_bx,  x86_64_with_base::lldb_bh,
    x86_64_with_base::lldb_bl,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rcx[] = {
    x86_64_with_base::lldb_rcx, x86_64_with_base::lldb_ecx,
    x86_64_with_base::lldb_cx,  x86_64_with_base::lldb_ch,
    x86_64_with_base::lldb_cl,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rdx[] = {
    x86_64_with_base::lldb_rdx, x86_64_with_base::lldb_edx,
    x86_64_with_base::lldb_dx,  x86_64_with_base::lldb_dh,
    x86_64_with_base::lldb_dl,  LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rdi[] = {
    x86_64_with_base::lldb_rdi, x86_64_with_base::lldb_edi,
    x86_64_with_base::lldb_di, x86_64_with_base::lldb_dil, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rsi[] = {
    x86_64_with_base::lldb_rsi, x86_64_with_base::lldb_esi,
    x86_64_with_base::lldb_si, x86_64_with_base::lldb_sil, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rbp[] = {
    x86_64_with_base::lldb_rbp, x86_64_with_base::lldb_ebp,
    x86_64_with_base::lldb_bp, x86_64_with_base::lldb_bpl, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_rsp[] = {
    x86_64_with_base::lldb_rsp, x86_64_with_base::lldb_esp,
    x86_64_with_base::lldb_sp, x86_64_with_base::lldb_spl, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r8[] = {
    x86_64_with_base::lldb_r8, x86_64_with_base::lldb_r8d,
    x86_64_with_base::lldb_r8w, x86_64_with_base::lldb_r8l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r9[] = {
    x86_64_with_base::lldb_r9, x86_64_with_base::lldb_r9d,
    x86_64_with_base::lldb_r9w, x86_64_with_base::lldb_r9l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r10[] = {
    x86_64_with_base::lldb_r10, x86_64_with_base::lldb_r10d,
    x86_64_with_base::lldb_r10w, x86_64_with_base::lldb_r10l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r11[] = {
    x86_64_with_base::lldb_r11, x86_64_with_base::lldb_r11d,
    x86_64_with_base::lldb_r11w, x86_64_with_base::lldb_r11l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r12[] = {
    x86_64_with_base::lldb_r12, x86_64_with_base::lldb_r12d,
    x86_64_with_base::lldb_r12w, x86_64_with_base::lldb_r12l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r13[] = {
    x86_64_with_base::lldb_r13, x86_64_with_base::lldb_r13d,
    x86_64_with_base::lldb_r13w, x86_64_with_base::lldb_r13l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r14[] = {
    x86_64_with_base::lldb_r14, x86_64_with_base::lldb_r14d,
    x86_64_with_base::lldb_r14w, x86_64_with_base::lldb_r14l,
    LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_r15[] = {
    x86_64_with_base::lldb_r15, x86_64_with_base::lldb_r15d,
    x86_64_with_base::lldb_r15w, x86_64_with_base::lldb_r15l,
    LLDB_INVALID_REGNUM};
static uint32_t g_contained_fip[] = {x86_64_with_base::lldb_fip,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_contained_fdp[] = {x86_64_with_base::lldb_fdp,
                                     LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_fip[] = {
    x86_64_with_base::lldb_fip, x86_64_with_base::lldb_fioff,
    x86_64_with_base::lldb_fiseg, LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_fdp[] = {
    x86_64_with_base::lldb_fdp, x86_64_with_base::lldb_fooff,
    x86_64_with_base::lldb_foseg, LLDB_INVALID_REGNUM};
static uint32_t g_contained_st0_64[] = {x86_64_with_base::lldb_st0,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st1_64[] = {x86_64_with_base::lldb_st1,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st2_64[] = {x86_64_with_base::lldb_st2,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st3_64[] = {x86_64_with_base::lldb_st3,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st4_64[] = {x86_64_with_base::lldb_st4,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st5_64[] = {x86_64_with_base::lldb_st5,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st6_64[] = {x86_64_with_base::lldb_st6,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_contained_st7_64[] = {x86_64_with_base::lldb_st7,
                                        LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st0_64[] = {x86_64_with_base::lldb_st0,
                                         x86_64_with_base::lldb_mm0,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st1_64[] = {x86_64_with_base::lldb_st1,
                                         x86_64_with_base::lldb_mm1,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st2_64[] = {x86_64_with_base::lldb_st2,
                                         x86_64_with_base::lldb_mm2,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st3_64[] = {x86_64_with_base::lldb_st3,
                                         x86_64_with_base::lldb_mm3,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st4_64[] = {x86_64_with_base::lldb_st4,
                                         x86_64_with_base::lldb_mm4,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st5_64[] = {x86_64_with_base::lldb_st5,
                                         x86_64_with_base::lldb_mm5,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st6_64[] = {x86_64_with_base::lldb_st6,
                                         x86_64_with_base::lldb_mm6,
                                         LLDB_INVALID_REGNUM};
static uint32_t g_invalidate_st7_64[] = {x86_64_with_base::lldb_st7,
                                         x86_64_with_base::lldb_mm7,
                                         LLDB_INVALID_REGNUM};
} // namespace RegisterInfos_x86_64_with_base_shared
} // namespace

// Convert the 8-bit abridged FPU Tag Word (as found in FXSAVE) to the full
// 16-bit FPU Tag Word (as found in FSAVE, and used by gdb protocol).  This
// requires knowing the values of the ST(i) registers and the FPU Status Word.
namespace lldb_private {

RegInfo &GetRegInfoShared(llvm::Triple::ArchType arch_type, bool with_base) {
  static std::once_flag once_flag_x86, once_flag_x86_64,
      once_flag_x86_64_with_base;
  static RegInfo reg_info_x86, reg_info_x86_64, reg_info_x86_64_with_base,
      reg_info_invalid;

  switch (arch_type) {
  case llvm::Triple::x86:
    std::call_once(once_flag_x86, []() {
      reg_info_x86.num_registers = k_num_registers_i386;
      reg_info_x86.num_gpr_registers = k_num_gpr_registers_i386;
      reg_info_x86.num_fpr_registers = k_num_fpr_registers_i386;
      reg_info_x86.num_avx_registers = k_num_avx_registers_i386;
      reg_info_x86.last_gpr = k_last_gpr_i386;
      reg_info_x86.first_fpr = k_first_fpr_i386;
      reg_info_x86.last_fpr = k_last_fpr_i386;
      reg_info_x86.first_st = lldb_st0_i386;
      reg_info_x86.last_st = lldb_st7_i386;
      reg_info_x86.first_mm = lldb_mm0_i386;
      reg_info_x86.last_mm = lldb_mm7_i386;
      reg_info_x86.first_xmm = lldb_xmm0_i386;
      reg_info_x86.last_xmm = lldb_xmm7_i386;
      reg_info_x86.first_ymm = lldb_ymm0_i386;
      reg_info_x86.last_ymm = lldb_ymm7_i386;
      reg_info_x86.first_dr = lldb_dr0_i386;
      reg_info_x86.gpr_flags = lldb_eflags_i386;
    });

    return reg_info_x86;
  case llvm::Triple::x86_64:
    if (with_base) {
      std::call_once(once_flag_x86_64_with_base, []() {
        reg_info_x86_64_with_base.num_registers =
            x86_64_with_base::k_num_registers;
        reg_info_x86_64_with_base.num_gpr_registers =
            x86_64_with_base::k_num_gpr_registers;
        reg_info_x86_64_with_base.num_fpr_registers =
            x86_64_with_base::k_num_fpr_registers;
        reg_info_x86_64_with_base.num_avx_registers =
            x86_64_with_base::k_num_avx_registers;
        reg_info_x86_64_with_base.last_gpr = x86_64_with_base::k_last_gpr;
        reg_info_x86_64_with_base.first_fpr = x86_64_with_base::k_first_fpr;
        reg_info_x86_64_with_base.last_fpr = x86_64_with_base::k_last_fpr;
        reg_info_x86_64_with_base.first_st = x86_64_with_base::lldb_st0;
        reg_info_x86_64_with_base.last_st = x86_64_with_base::lldb_st7;
        reg_info_x86_64_with_base.first_mm = x86_64_with_base::lldb_mm0;
        reg_info_x86_64_with_base.last_mm = x86_64_with_base::lldb_mm7;
        reg_info_x86_64_with_base.first_xmm = x86_64_with_base::lldb_xmm0;
        reg_info_x86_64_with_base.last_xmm = x86_64_with_base::lldb_xmm15;
        reg_info_x86_64_with_base.first_ymm = x86_64_with_base::lldb_ymm0;
        reg_info_x86_64_with_base.last_ymm = x86_64_with_base::lldb_ymm15;
        reg_info_x86_64_with_base.first_dr = x86_64_with_base::lldb_dr0;
        reg_info_x86_64_with_base.gpr_flags = x86_64_with_base::lldb_rflags;
      });

      return reg_info_x86_64_with_base;
    } else {
      std::call_once(once_flag_x86_64, []() {
        reg_info_x86_64.num_registers = k_num_registers_x86_64;
        reg_info_x86_64.num_gpr_registers = k_num_gpr_registers_x86_64;
        reg_info_x86_64.num_fpr_registers = k_num_fpr_registers_x86_64;
        reg_info_x86_64.num_avx_registers = k_num_avx_registers_x86_64;
        reg_info_x86_64.last_gpr = k_last_gpr_x86_64;
        reg_info_x86_64.first_fpr = k_first_fpr_x86_64;
        reg_info_x86_64.last_fpr = k_last_fpr_x86_64;
        reg_info_x86_64.first_st = lldb_st0_x86_64;
        reg_info_x86_64.last_st = lldb_st7_x86_64;
        reg_info_x86_64.first_mm = lldb_mm0_x86_64;
        reg_info_x86_64.last_mm = lldb_mm7_x86_64;
        reg_info_x86_64.first_xmm = lldb_xmm0_x86_64;
        reg_info_x86_64.last_xmm = lldb_xmm15_x86_64;
        reg_info_x86_64.first_ymm = lldb_ymm0_x86_64;
        reg_info_x86_64.last_ymm = lldb_ymm15_x86_64;
        reg_info_x86_64.first_dr = lldb_dr0_x86_64;
        reg_info_x86_64.gpr_flags = lldb_rflags_x86_64;
      });
      return reg_info_x86_64;
    }
  default:
    assert(false && "Unhandled target architecture.");
    return reg_info_invalid;
  }
}

} // namespace lldb_private

static uint32_t FPRValueByteSize(llvm::StringRef field) {
  if (field == "ptr.x86_64.fip" || field == "ptr.x86_64.fdp")
    return 8;
  if (field.starts_with("ptr.i386_.") || field == "mxcsr" ||
      field == "mxcsrmask")
    return 4;
  return 2;
}

static llvm::ArrayRef<RegisterInfo> Metadata_i386() {
  constexpr uint32_t word_size = 4;
#include "Register/Arch/RegisterDescriptions_i386.inc"
  return g_register_infos_i386;
}
static llvm::ArrayRef<RegisterInfo> Metadata_x86_64() {
  constexpr uint32_t word_size = 8;
#include "Register/Arch/RegisterDescriptions_x86_64.inc"
  return g_register_infos_x86_64;
}
static llvm::ArrayRef<RegisterInfo> Metadata_x86_64_with_base() {
  constexpr uint32_t word_size = 8;
#include "Register/Arch/RegisterDescriptions_x86_64_with_base.inc"
  return g_register_infos_x86_64_with_base;
}

namespace {
// A value profile selects exposed CPU registers and widths, not storage slots.
struct ValueSpec {
  const char *name;
  uint32_t byte_size;
};
std::shared_ptr<const RegisterDescription>
BuildDescription(const ArchSpec &arch, llvm::ArrayRef<ValueSpec> entries,
                 bool with_segment_bases, X86RegisterABI abi,
                 X86RegisterMode mode) {
  const bool is_64 = mode == X86RegisterMode::X86_64 ||
                     (mode == X86RegisterMode::Target &&
                      arch.GetMachine() == llvm::Triple::x86_64);
  auto base_rows = is_64 ? Metadata_x86_64() : Metadata_i386();
  auto rows =
      is_64 && with_segment_bases ? Metadata_x86_64_with_base() : base_rows;
  auto base = llvm::cantFail(RegisterDescription::FromLegacy(base_rows));
  auto source = llvm::cantFail(RegisterDescription::FromLegacy(rows));
  std::map<RegisterID, RegisterID> identities;
  RegisterID next_id = 0;
  for (const auto &reg : base.GetRegisters())
    next_id = std::max(next_id, reg.id + 1);
  for (const auto &reg : source.GetRegisters()) {
    const auto *canonical = base.Find(reg.name);
    identities[reg.id] = canonical ? canonical->id : next_id++;
  }
  std::vector<RegisterDescriptor> registers;
  std::set<RegisterID> selected;
  for (const auto &entry : entries) {
    const auto *original = entry.name ? source.Find(entry.name) : nullptr;
    if (!original)
      llvm::report_fatal_error("unknown x86 register in saved-state layout");
    auto reg = *original;
    reg.id = identities.at(reg.id);
    reg.byte_size = entry.byte_size;
    if ((reg.name == "fiseg" || reg.name == "foseg") &&
        reg.value_registers.size() == 1)
      reg.value_byte_offset = 4;
    for (auto *references : {&reg.value_registers, &reg.invalidate_registers})
      for (auto &id : *references)
        id = identities.at(id);
    if (abi == X86RegisterABI::Windows && is_64) {
      uint32_t &generic = reg.numbers[eRegisterKindGeneric];
      if (generic >= LLDB_REGNUM_GENERIC_ARG1 &&
          generic <= LLDB_REGNUM_GENERIC_ARG8)
        generic = LLDB_INVALID_REGNUM;
      for (auto pair : {std::make_pair("rcx", LLDB_REGNUM_GENERIC_ARG1),
                        std::make_pair("rdx", LLDB_REGNUM_GENERIC_ARG2),
                        std::make_pair("r8", LLDB_REGNUM_GENERIC_ARG3),
                        std::make_pair("r9", LLDB_REGNUM_GENERIC_ARG4)})
        if (reg.name == pair.first)
          generic = pair.second;
    }
    if (abi == X86RegisterABI::Windows &&
        llvm::StringRef(reg.name).starts_with("xmm")) {
      reg.encoding = eEncodingUint;
      reg.format = eFormatVectorOfUInt64;
    }
    if (is_64 && reg.byte_size == 4 && !reg.value_registers.empty() &&
        (llvm::StringRef(reg.name).starts_with("e") ||
         (llvm::StringRef(reg.name).starts_with("r") &&
          llvm::StringRef(reg.name).ends_with("d"))))
      reg.zero_extend_parent = reg.value_registers.front();
    selected.insert(reg.id);
    registers.push_back(std::move(reg));
  }
  for (auto &reg : registers) {
    llvm::erase_if(reg.invalidate_registers,
                   [&](RegisterID id) { return !selected.count(id); });
    llvm::erase_if(reg.value_registers,
                   [&](RegisterID id) { return !selected.count(id); });
  }
  std::vector<RegisterGroup> groups = {
      {"General Purpose Registers", "gpr", {}},
      {"Floating Point Registers", "fpu", {}},
      {"Advanced Vector Extensions", "avx", {}},
      {"Memory Protection Extensions", "mpx", {}},
      {"Hardware Debug Registers", "dbr", {}}};
  const auto &ranges =
      GetRegInfoShared(is_64 ? llvm::Triple::x86_64 : llvm::Triple::x86,
                       is_64 && with_segment_bases);
  for (const auto &reg : registers) {
    llvm::StringRef name(reg.name);
    size_t group = reg.numbers[eRegisterKindLLDB] < ranges.first_fpr ? 0 : 1;
    if (name.starts_with("ymm"))
      group = 2;
    if (name.starts_with("bnd"))
      group = 3;
    if (name.size() > 2 && name.starts_with("dr"))
      group = 4;
    groups[group].registers.push_back(reg.id);
  }
  llvm::erase_if(groups, [](const RegisterGroup &group) {
    return group.registers.empty();
  });
  return std::make_shared<RegisterDescription>(llvm::cantFail(
      RegisterDescription::Create(std::move(registers), std::move(groups))));
}

} // namespace

std::shared_ptr<const RegisterDescription> RegisterInfo_x86::CreateDescription(
    const ArchSpec &arch, bool with_segment_bases, X86RegisterABI abi,
    X86RegisterMode mode, X86RegisterProfile profile) {
  bool is_64 = mode == X86RegisterMode::X86_64 ||
               (mode == X86RegisterMode::Target &&
                arch.GetMachine() == llvm::Triple::x86_64);
  auto rows = is_64 ? (with_segment_bases ? Metadata_x86_64_with_base()
                                          : Metadata_x86_64())
                    : Metadata_i386();
  std::vector<ValueSpec> values;
  for (const auto &row : rows)
    values.push_back({row.name, row.byte_size});
  auto complete = BuildDescription(arch, values, with_segment_bases, abi, mode);
  std::vector<RegisterGroup> groups;
  std::set<RegisterID> selected;
  for (auto group : complete->GetGroups()) {
    llvm::erase_if(group.registers, [&](RegisterID id) {
      const auto *reg = complete->Find(id);
      if (group.short_name == "gpr") {
        const bool segment = llvm::is_contained(
            {"cs", "ds", "es", "fs", "gs", "ss", "fs_base", "gs_base"},
            llvm::StringRef(reg->name));
        return (!profile.segments && segment) ||
               (!profile.gpr_aliases && !reg->value_registers.empty());
      }
      if (group.short_name == "fpu")
        return llvm::StringRef(reg->name).starts_with("xmm") ? !profile.simd
                                                             : !profile.x87;
      if (group.short_name == "avx")
        return !profile.avx;
      if (group.short_name == "mpx")
        return !profile.mpx;
      if (group.short_name == "dbr")
        return !profile.debug;
      return false;
    });
    selected.insert(group.registers.begin(), group.registers.end());
    if (!group.registers.empty())
      groups.push_back(std::move(group));
  }
  std::vector<RegisterDescriptor> regs;
  for (auto reg : complete->GetRegisters()) {
    if (!selected.count(reg.id))
      continue;
    for (auto *refs : {&reg.value_registers, &reg.invalidate_registers})
      llvm::erase_if(*refs, [&](RegisterID id) { return !selected.count(id); });
    if (!selected.count(reg.zero_extend_parent))
      reg.zero_extend_parent = LLDB_INVALID_REGNUM;
    regs.push_back(std::move(reg));
  }
  return std::make_shared<RegisterDescription>(llvm::cantFail(
      RegisterDescription::Create(std::move(regs), std::move(groups))));
}

uint16_t lldb_private::AbridgedToFullTagWord(uint8_t abridged_tw, uint16_t sw,
                                             llvm::ArrayRef<MMSReg> st_regs) {
  // Tag word is using internal FPU register numbering rather than ST(i).
  // Mapping to ST(i): i = FPU regno - TOP (Status Word, bits 11:13).
  // Here we start with FPU reg 7 and go down.
  int st = 7 - ((sw >> 11) & 7);
  uint16_t tw = 0;
  for (uint8_t mask = 0x80; mask != 0; mask >>= 1) {
    tw <<= 2;
    if (abridged_tw & mask) {
      // The register is non-empty, so we need to check the value of ST(i).
      uint16_t exp =
          st_regs[st].comp.sign_exp & 0x7fff; // Discard the sign bit.
      if (exp == 0) {
        if (st_regs[st].comp.mantissa == 0)
          tw |= 1; // Zero
        else
          tw |= 2; // Denormal
      } else if (exp == 0x7fff)
        tw |= 2; // Infinity or NaN
      // 0 if normal number
    } else
      tw |= 3; // Empty register

    // Rotate ST down.
    st = (st - 1) & 7;
  }

  return tw;
}

// Convert the 16-bit FPU Tag Word to the abridged 8-bit value, to be written
// into FXSAVE.
uint8_t lldb_private::FullToAbridgedTagWord(uint16_t tw) {
  uint8_t abridged_tw = 0;
  for (uint16_t mask = 0xc000; mask != 0; mask >>= 2) {
    abridged_tw <<= 1;
    // full TW uses 11 for empty registers, aTW uses 0
    if ((tw & mask) != mask)
      abridged_tw |= 1;
  }
  return abridged_tw;
}

RegisterModel lldb_private::CreateX86RegisterModel(
    const ArchSpec &arch, llvm::ArrayRef<RegisterStorageField> gpr_fields,
    size_t gpr_size, bool gpr_is_64, bool segment_bases, X86RegisterABI abi) {
  using namespace x86_layout;
  auto cpu = RegisterInfo_x86::CreateDescription(arch, segment_bases, abi);
  std::vector<RegisterDescriptor> regs(cpu->GetRegisters().begin(),
                                       cpu->GetRegisters().end());
  std::vector<RegisterGroup> groups(cpu->GetGroups().begin(),
                                    cpu->GetGroups().end());
  RegisterLayout layout(arch.GetByteOrder());
  llvm::cantFail(layout.AddBank(GP, gpr_size));
  llvm::cantFail(layout.AddBank(FP, sizeof(FXSAVE)));
  llvm::cantFail(layout.AddBank(YMMHigh, 256));
  llvm::cantFail(layout.AddBank(Bounds, 64));
  llvm::cantFail(layout.AddBank(BoundsControl, 16));
  llvm::cantFail(layout.AddBank(Debug, 8 * (gpr_is_64 ? 8 : 4)));
  auto field = [&](llvm::StringRef name) -> const RegisterStorageField * {
    if (gpr_is_64 && arch.GetMachine() == llvm::Triple::x86) {
      if (name == "eflags")
        name = "rflags";
      else if (name.starts_with("e")) {
        std::string wide = "r" + name.drop_front().str();
        for (const auto &value : gpr_fields)
          if (wide == value.name)
            return &value;
      }
    }
    for (const auto &value : gpr_fields)
      if (name == value.name)
        return &value;
    return nullptr;
  };
  std::map<RegisterID, RegisterLocation> locations;
  auto stored = [&](RegisterID id, RegisterBankID bank, uint32_t offset,
                    uint32_t size) {
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({bank, offset, size});
    locations.emplace(id, std::move(location));
  };
  for (auto &reg : regs) {
    if (auto *slot = field(reg.name)) {
      reg.byte_size = std::min(reg.byte_size, slot->byte_size);
      stored(reg.id, GP, slot->byte_offset, reg.byte_size);
      continue;
    }
    llvm::StringRef name(reg.name);
    unsigned index;
    auto indexed = [&](llvm::StringRef prefix) {
      return name.consume_front(prefix) && !name.getAsInteger(10, index);
    };
    name = reg.name;
    if (indexed("ymm")) {
      RegisterLocation location;
      location.kind = RegisterLocation::Stored;
      location.pieces = {{FP, offsetof(FXSAVE, xmm) + index * 16, 16, 0},
                         {YMMHigh, index * 16, 16, 16}};
      locations.emplace(reg.id, std::move(location));
      continue;
    }
    name = reg.name;
    if (indexed("xmm")) {
      stored(reg.id, FP, offsetof(FXSAVE, xmm) + index * 16, reg.byte_size);
      continue;
    }
    name = reg.name;
    if (indexed("st")) {
      stored(reg.id, FP, offsetof(FXSAVE, stmm) + index * 16, reg.byte_size);
      continue;
    }
    name = reg.name;
    if (indexed("mm")) {
      stored(reg.id, FP, offsetof(FXSAVE, stmm) + index * 16, reg.byte_size);
      continue;
    }
    name = reg.name;
    if (indexed("dr")) {
      stored(reg.id, Debug, index * (gpr_is_64 ? 8 : 4), reg.byte_size);
      continue;
    }
    name = reg.name;
    if (indexed("bnd")) {
      stored(reg.id, Bounds, index * 16, reg.byte_size);
      continue;
    }
    if (reg.name == "bndcfgu") {
      stored(reg.id, BoundsControl, 0, reg.byte_size);
      continue;
    }
    if (reg.name == "bndstatus") {
      stored(reg.id, BoundsControl, 8, reg.byte_size);
      continue;
    }
    struct FPField {
      const char *name;
      uint32_t offset;
    };
    const FPField scalars[] = {{"fctrl", offsetof(FXSAVE, fctrl)},
                               {"fstat", offsetof(FXSAVE, fstat)},
                               {"ftag", offsetof(FXSAVE, ftag)},
                               {"fop", offsetof(FXSAVE, fop)},
                               {"fiseg", offsetof(FXSAVE, ptr.i386_.fiseg)},
                               {"fioff", offsetof(FXSAVE, ptr.i386_.fioff)},
                               {"foseg", offsetof(FXSAVE, ptr.i386_.foseg)},
                               {"fooff", offsetof(FXSAVE, ptr.i386_.fooff)},
                               {"fip", offsetof(FXSAVE, ptr.x86_64.fip)},
                               {"fdp", offsetof(FXSAVE, ptr.x86_64.fdp)},
                               {"mxcsr", offsetof(FXSAVE, mxcsr)},
                               {"mxcsrmask", offsetof(FXSAVE, mxcsrmask)}};
    for (const auto &slot : scalars)
      if (reg.name == slot.name)
        stored(reg.id, FP, slot.offset, reg.byte_size);
  }
  // GPR aliases use their architecture value relation, never slot subtraction.
  for (size_t pass = 0; pass < regs.size(); ++pass)
    for (const auto &reg : regs) {
      if (locations.count(reg.id) || reg.value_registers.size() != 1)
        continue;
      auto parent = locations.find(reg.value_registers.front());
      if (parent == locations.end() || parent->second.pieces.size() != 1 ||
          parent->second.pieces.front().bank != GP)
        continue;
      const auto &piece = parent->second.pieces.front();
      stored(reg.id, GP, piece.byte_offset + reg.value_byte_offset,
             reg.byte_size);
    }
  uint32_t user_count = regs.size();
  for (const auto &reg : regs)
    if (llvm::StringRef(reg.name).starts_with("dr"))
      --user_count;
  auto description = std::make_shared<RegisterDescription>(llvm::cantFail(
      RegisterDescription::Create(std::move(regs), std::move(groups))));
  for (auto &[id, location] : locations)
    llvm::cantFail(layout.Add(id, std::move(location)));
  llvm::cantFail(layout.Validate(*description));
  return {std::move(description), std::move(layout), user_count};
}
