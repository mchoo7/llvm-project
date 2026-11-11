//===-- NativeRegisterContextFreeBSD_powerpc.h ------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__powerpc__)

#ifndef lldb_NativeRegisterContextFreeBSD_powerpc_h
#define lldb_NativeRegisterContextFreeBSD_powerpc_h

// clang-format off
#include <sys/types.h>
#include <machine/reg.h>
// clang-format on

#include "Plugins/Process/FreeBSD/NativeRegisterContextFreeBSD.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_powerpc.h"

#include <array>

namespace lldb_private {
namespace process_freebsd {

class NativeProcessFreeBSD;

class NativeRegisterContextFreeBSD_powerpc
    : public NativeRegisterContextFreeBSD {
public:
  NativeRegisterContextFreeBSD_powerpc(const ArchSpec &target_arch,
                                       NativeThreadFreeBSD &native_thread,
                                       bool has_vmx = false,
                                       bool has_vsx = false);

  llvm::Expected<lldb_private::RegisterValue>
  ReadRegister(lldb_private::RegisterID id) override;

  llvm::Error
  WriteRegister(lldb_private::RegisterID id,
                const lldb_private::RegisterValue &reg_value) override;

  Status ReadAllRegisterValues(lldb::WritableDataBufferSP &data_sp) override;

  Status WriteAllRegisterValues(const lldb::DataBufferSP &data_sp) override;

  llvm::Error
  CopyHardwareWatchpointsFrom(NativeRegisterContextFreeBSD &source) override;

private:
  enum RegSetKind {
    GPRegSet,
    FPRegSet,
    VMXRegSet,
    VSXRegSet,
  };
  reg m_gpr{};
  fpreg m_fpr{};
  vmxreg m_vmx{};
  freebsd_powerpc::VSX m_vsx{};
  bool m_has_vmx;
  bool m_has_vsx;

  std::array<MutableRegisterData, 4> GetRegisterBanks();
  bool HasRegisterSet(RegSetKind set) const;

  Status ReadRegisterSet(RegSetKind set);
  Status WriteRegisterSet(RegSetKind set);
};

} // namespace process_freebsd
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextFreeBSD_powerpc_h

#endif // defined (__powerpc__)
