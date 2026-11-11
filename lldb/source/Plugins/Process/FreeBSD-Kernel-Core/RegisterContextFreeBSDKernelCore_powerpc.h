//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_POWERPC_H
#define LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_POWERPC_H

#include "lldb/Register/Common/RegisterInfo_ppc64.h"
#include "lldb/Register/Common/RegisterInfo_ppc64le.h"
#include "lldb/Register/RegisterLayout.h"
#include "lldb/Target/ThreadRegisterContext.h"
#include "lldb/Utility/ArchSpec.h"
#include <cassert>
#include <cstddef>
#include <cstdint>

namespace lldb_private {
namespace freebsd_kernel {

// Only the prefix used by cpu_switch and savectx; subsequent PCB fields may
// change without affecting this layout. Values are decoded in target byte
// order.
struct PowerPCPCB64 {
  uint64_t context[20]; // r12-r31
  uint64_t cr, sp, toc, lr;
};

inline RegisterLayout CreatePowerPCRegisterLayout(const ArchSpec &arch,
                                                  lldb::addr_t thread_address) {
  auto description = arch.GetMachine() == llvm::Triple::ppc64le
                         ? RegisterInfo_ppc64le::CreateDescription(arch)
                         : RegisterInfo_ppc64::CreateDescription(
                               arch, RegisterInfo_ppc64::Numbering::ELF);
  RegisterLayout layout(arch.GetByteOrder());
  llvm::cantFail(layout.AddBank(0, sizeof(PowerPCPCB64)));
  auto add = [&](const std::string &name, uint32_t offset) {
    const auto *reg = description->Find(name);
    assert(reg && "unknown PowerPC register");
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({0, offset, reg->byte_size});
    llvm::cantFail(layout.Add(reg->id, std::move(location)));
  };
  for (unsigned i = 12; i != 32; ++i) {
    // cpu_switch does not save r13: the kernel keeps curthread in it.
    if (i == 13)
      continue;
    add("r" + std::to_string(i),
        offsetof(PowerPCPCB64, context) + (i - 12) * sizeof(uint64_t));
  }
  if (thread_address != LLDB_INVALID_ADDRESS) {
    RegisterLocation curthread;
    curthread.kind = RegisterLocation::Constant;
    curthread.constant.resize(8);
    for (unsigned i = 0; i != 8; ++i) {
      unsigned byte = arch.GetByteOrder() == lldb::eByteOrderBig ? 7 - i : i;
      curthread.constant[byte] =
          static_cast<uint8_t>(thread_address >> (i * 8));
    }
    llvm::cantFail(
        layout.Add(description->Find("r13")->id, std::move(curthread)));
  }
  add("r1", offsetof(PowerPCPCB64, sp));
  add("r2", offsetof(PowerPCPCB64, toc));
  add("cr", offsetof(PowerPCPCB64, cr));
  add("lr", offsetof(PowerPCPCB64, lr));
  // savectx saves the continuation PC in the link register.
  add("pc", offsetof(PowerPCPCB64, lr));
  return llvm::cantFail(
      RegisterLayout::Create(std::move(description), std::move(layout)));
}

} // namespace freebsd_kernel
} // namespace lldb_private

class RegisterContextFreeBSDKernelCore_powerpc
    : public lldb_private::ThreadRegisterContext {
public:
  RegisterContextFreeBSDKernelCore_powerpc(lldb_private::Thread &thread,
                                           lldb_private::RegisterLayout layout,
                                           lldb::addr_t pcb_addr);

  llvm::Expected<lldb_private::RegisterValue>
  ReadRegister(lldb_private::RegisterID id) override;

  llvm::Error WriteRegister(lldb_private::RegisterID id,
                     const lldb_private::RegisterValue &value) override;

private:
  lldb::addr_t m_pcb_addr;
};

#endif // LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_POWERPC_H
