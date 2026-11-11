//===-- NativeRegisterContextFreeBSD.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "NativeRegisterContextFreeBSD.h"
#include "lldb/Utility/ArchSpec.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"

#include "lldb/Host/common/NativeProcessProtocol.h"

#if defined(__powerpc__)
#include "NativeRegisterContextFreeBSD_ppc32be.h"
#if defined(__powerpc64__)
#include "NativeRegisterContextFreeBSD_ppc64.h"
#include "NativeRegisterContextFreeBSD_ppc64le.h"
#endif
#include <array>
#endif

using namespace lldb_private;
using namespace lldb_private::process_freebsd;

// clang-format off
#include <sys/types.h>
#include <sys/ptrace.h>
// clang-format on

NativeProcessFreeBSD &NativeRegisterContextFreeBSD::GetProcess() {
  return static_cast<NativeProcessFreeBSD &>(m_thread.GetProcess());
}

::pid_t NativeRegisterContextFreeBSD::GetProcessPid() {
  return GetProcess().GetID();
}

#if defined(__powerpc__)
NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &arch, NativeThreadFreeBSD &thread) {
  switch (arch.GetMachine()) {
  case llvm::Triple::ppc:
    return new NativeRegisterContextFreeBSD_ppc32be(arch, thread);
#if defined(__powerpc64__)
  case llvm::Triple::ppc64: {
    vmxreg vmx{};

    bool has_vmx =
        NativeProcessFreeBSD::PtraceWrapper(PT_GETVRREGS, thread.GetID(), &vmx)
            .Success();
    std::array<uint64_t, 32> vsx{};

    bool has_vsx = has_vmx && NativeProcessFreeBSD::PtraceWrapper(
                                  PT_GETVSRREGS, thread.GetID(), vsx.data())
                                  .Success();

    return new NativeRegisterContextFreeBSD_ppc64(arch, thread, has_vmx,
                                                  has_vsx);
  }
  case llvm::Triple::ppc64le: {
    vmxreg vmx{};

    bool has_vmx =
        NativeProcessFreeBSD::PtraceWrapper(PT_GETVRREGS, thread.GetID(), &vmx)
            .Success();
    std::array<uint64_t, 32> vsx{};

    bool has_vsx = has_vmx && NativeProcessFreeBSD::PtraceWrapper(
                                  PT_GETVSRREGS, thread.GetID(), vsx.data())
                                  .Success();

    return new NativeRegisterContextFreeBSD_ppc64le(arch, thread, has_vmx,
                                                    has_vsx);
  }
#endif
  default:
    llvm_unreachable("unsupported native FreeBSD PowerPC architecture");
  }
}
#endif
