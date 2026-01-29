//===-- RegisterContextFreeBSD_powerpc.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//

#include "RegisterContextFreeBSD_ppc64le.h"
#include "RegisterContextPOSIX_ppc64le.h"
#include <vector>

using namespace lldb_private;
using namespace lldb;

// https://github.com/freebsd/freebsd-src/blob/main/sys/powerpc/include/reg.h
typedef struct _GPR {
  uint64_t r0;
  uint64_t r1;
  uint64_t r2;
  uint64_t r3;
  uint64_t r4;
  uint64_t r5;
  uint64_t r6;
  uint64_t r7;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t r16;
  uint64_t r17;
  uint64_t r18;
  uint64_t r19;
  uint64_t r20;
  uint64_t r21;
  uint64_t r22;
  uint64_t r23;
  uint64_t r24;
  uint64_t r25;
  uint64_t r26;
  uint64_t r27;
  uint64_t r28;
  uint64_t r29;
  uint64_t r30;
  uint64_t r31;
  uint64_t lr;
  uint64_t cr;
  uint64_t xer;
  uint64_t ctr;
  uint64_t pc;
} GPR;

typedef struct _FPR {
  uint64_t f0;
  uint64_t f1;
  uint64_t f2;
  uint64_t f3;
  uint64_t f4;
  uint64_t f5;
  uint64_t f6;
  uint64_t f7;
  uint64_t f8;
  uint64_t f9;
  uint64_t f10;
  uint64_t f11;
  uint64_t f12;
  uint64_t f13;
  uint64_t f14;
  uint64_t f15;
  uint64_t f16;
  uint64_t f17;
  uint64_t f18;
  uint64_t f19;
  uint64_t f20;
  uint64_t f21;
  uint64_t f22;
  uint64_t f23;
  uint64_t f24;
  uint64_t f25;
  uint64_t f26;
  uint64_t f27;
  uint64_t f28;
  uint64_t f29;
  uint64_t f30;
  uint64_t f31;
  uint64_t fpscr;
} FPR;

typedef struct _VMX {
  uint32_t v0[4];
  uint32_t v1[4];
  uint32_t v2[4];
  uint32_t v3[4];
  uint32_t v4[4];
  uint32_t v5[4];
  uint32_t v6[4];
  uint32_t v7[4];
  uint32_t v8[4];
  uint32_t v9[4];
  uint32_t v10[4];
  uint32_t v11[4];
  uint32_t v12[4];
  uint32_t v13[4];
  uint32_t v14[4];
  uint32_t v15[4];
  uint32_t v16[4];
  uint32_t v17[4];
  uint32_t v18[4];
  uint32_t v19[4];
  uint32_t v20[4];
  uint32_t v21[4];
  uint32_t v22[4];
  uint32_t v23[4];
  uint32_t v24[4];
  uint32_t v25[4];
  uint32_t v26[4];
  uint32_t v27[4];
  uint32_t v28[4];
  uint32_t v29[4];
  uint32_t v30[4];
  uint32_t v31[4];
  uint32_t pad[2];
  uint32_t vrsave;
  uint32_t vscr;
} VMX;

// Include RegisterInfos_powerpc to declare our g_register_infos_powerpc
// structure.
#define DECLARE_REGISTER_INFOS_POWERPC_STRUCT
#include "RegisterInfos_ppc64le.h"
#undef DECLARE_REGISTER_INFOS_POWERPC_STRUCT

RegisterContextFreeBSD_ppc64le::RegisterContextFreeBSD_ppc64le(
    const ArchSpec &target_arch)
    : RegisterInfoInterface(target_arch) {}

RegisterContextFreeBSD_ppc64le::~RegisterContextFreeBSD_ppc64le() = default;

size_t RegisterContextFreeBSD_ppc64le::GetGPRSize() const {
  return sizeof(GPR);
}

const RegisterInfo *RegisterContextFreeBSD_ppc64le::GetRegisterInfo() const {
  return g_register_infos_ppc64le;
}

uint32_t RegisterContextFreeBSD_ppc64le::GetRegisterCount() const {
  return static_cast<uint32_t>(sizeof(g_register_infos_ppc64le) /
                               sizeof(g_register_infos_ppc64le[0]));
}
