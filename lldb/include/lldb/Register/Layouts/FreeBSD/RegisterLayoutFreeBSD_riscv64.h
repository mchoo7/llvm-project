//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERLAYOUTFREEBSD_RISCV64_H
#define LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERLAYOUTFREEBSD_RISCV64_H

#include "lldb/Register/RegisterLayout.h"
#include <cstdint>

namespace lldb_private {
class ArchSpec;

namespace freebsd_riscv64 {
// FreeBSD's ptrace and ELF core-note ABI, independent of the reader's host.
struct alignas(8) GPR {
  uint64_t ra, sp, gp, tp;
  uint64_t t[7], s[12], a[8];
  uint64_t sepc, sstatus;
};
struct alignas(8) FPR {
  uint64_t x[32][2];
  uint64_t fcsr;
};
static_assert(sizeof(GPR) == 264);
static_assert(sizeof(FPR) == 520);
} // namespace freebsd_riscv64

RegisterLayout CreateFreeBSDRISCV64RegisterLayout(const ArchSpec &arch,
                                                  bool has_fp);
} // namespace lldb_private

#endif
