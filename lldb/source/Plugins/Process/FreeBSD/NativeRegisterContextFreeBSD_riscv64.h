//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_FREEBSD_NATIVEREGISTERCONTEXTFREEBSD_RISCV64_H
#define LLDB_SOURCE_PLUGINS_PROCESS_FREEBSD_NATIVEREGISTERCONTEXTFREEBSD_RISCV64_H

#if defined(__riscv) && __riscv_xlen == 64

#include "NativeRegisterContextFreeBSD.h"
#include "lldb/Register/Layouts/FreeBSD/RegisterLayoutFreeBSD_riscv64.h"

namespace lldb_private {
namespace process_freebsd {

class NativeRegisterContextFreeBSD_riscv64
    : public NativeRegisterContextFreeBSD {
public:
  NativeRegisterContextFreeBSD_riscv64(const ArchSpec &arch,
                                       NativeThreadFreeBSD &thread,
                                       bool has_fp);

  llvm::Expected<RegisterValue> ReadRegister(RegisterID id) override;
  llvm::Error WriteRegister(RegisterID id, const RegisterValue &value) override;
  Status ReadAllRegisterValues(lldb::WritableDataBufferSP &data) override;
  Status WriteAllRegisterValues(const lldb::DataBufferSP &data) override;
  llvm::Error
  CopyHardwareWatchpointsFrom(NativeRegisterContextFreeBSD &source) override;

private:
  Status ReadBank(RegisterBankID bank);
  Status WriteBank(RegisterBankID bank);
  bool m_has_fp;
  freebsd_riscv64::GPR m_gpr{};
  freebsd_riscv64::FPR m_fpr{};
};

} // namespace process_freebsd
} // namespace lldb_private

#endif
#endif
