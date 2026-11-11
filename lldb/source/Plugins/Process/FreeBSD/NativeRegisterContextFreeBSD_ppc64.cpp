//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__powerpc64__)

#include "NativeRegisterContextFreeBSD_ppc64.h"
#include "NativeThreadFreeBSD.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_ppc.h"
#include "lldb/Utility/ArchSpec.h"

using namespace lldb_private;
using namespace lldb_private::process_freebsd;

NativeRegisterContextFreeBSD_ppc64::NativeRegisterContextFreeBSD_ppc64(
    const ArchSpec &arch, NativeThreadFreeBSD &thread, bool has_vmx,
    bool has_vsx)
    : NativeRegisterContext(
          thread, arch,
          SelectLayout(RegisterLayoutFreeBSD_ppc(arch, has_vsx), has_vmx,
                       has_vsx)),
      NativeRegisterContextFreeBSD_ppc(has_vmx, has_vsx) {}

llvm::Error NativeRegisterContextFreeBSD_ppc64::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
  return llvm::Error::success();
}

#endif // defined(__powerpc64__)
