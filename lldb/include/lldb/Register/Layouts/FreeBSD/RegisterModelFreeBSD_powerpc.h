//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERMODELFREEBSD_POWERPC_H
#define LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERMODELFREEBSD_POWERPC_H
#include "lldb/Register/Common/RegisterInfo_powerpc.h"

namespace lldb_private {
RegisterModel CreateFreeBSDPowerPC32RegisterModel(const ArchSpec &arch);
RegisterModel CreateFreeBSDPowerPC64RegisterModel(const ArchSpec &arch);
} // namespace lldb_private
#endif
