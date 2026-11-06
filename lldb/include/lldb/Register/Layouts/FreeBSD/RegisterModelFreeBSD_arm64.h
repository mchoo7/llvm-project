//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERMODELFREEBSD_ARM64_H
#define LLDB_REGISTER_LAYOUTS_FREEBSD_REGISTERMODELFREEBSD_ARM64_H
#include "lldb/Register/Common/RegisterInfo_arm64.h"
#include "lldb/Utility/ArchSpec.h"
namespace lldb_private {
Arm64RegisterFeatures DecodeFreeBSDArm64RegisterFeatures(uint64_t hwcap,
                                                         uint64_t hwcap2);
RegisterModel CreateFreeBSDArm64RegisterModel(const ArchSpec &arch,
                                              uint64_t hwcap = 0,
                                              uint64_t hwcap2 = 0);
} // namespace lldb_private
#endif
