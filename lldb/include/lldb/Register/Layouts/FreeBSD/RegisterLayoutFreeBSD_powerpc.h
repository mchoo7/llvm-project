//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERLAYOUTFREEBSD_POWERPC_H
#define LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERLAYOUTFREEBSD_POWERPC_H
#include "lldb/Register/Common/RegisterInfo_powerpc.h"
#include "lldb/Register/RegisterLayout.h"

namespace lldb_private {
namespace freebsd_powerpc {
struct VSX {
  // PT_GETVSRREGS stores doubleword 1 of VSR0-31, not the complete VSRs.
  uint64_t extra[32];
};
static_assert(sizeof(VSX) == 256);
} // namespace freebsd_powerpc

RegisterLayout CreateFreeBSDPowerPC32RegisterLayout(const ArchSpec &arch);
RegisterLayout CreateFreeBSDPowerPC64RegisterLayout(const ArchSpec &arch,
                                                    bool has_vsx = false);
} // namespace lldb_private
#endif
