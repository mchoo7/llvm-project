//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_PPC_H
#define LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_PPC_H

#include "lldb/Register/Descriptions/RegisterDescription_ppc32be.h"
#include "lldb/Register/RegisterLayout.h"
#include "lldb/Target/ThreadRegisterContext.h"
#include "lldb/Utility/ArchSpec.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace lldb_private::freebsd_kernel {

// The prefix saved by cpu_switch and savectx, decoded in target byte order.
struct PPCPCB {
  uint32_t context[20]; // r12-r31
  uint32_t cr, sp, toc, lr;
};

inline RegisterLayout
CreateRegisterLayoutFreeBSDKernelCore_ppc32be(const ArchSpec &arch,
                                              lldb::addr_t /*thread_address*/) {
  assert(arch.GetMachine() == llvm::Triple::ppc);
  auto description = RegisterDescription_ppc32be::GetShared();
  using PCB = PPCPCB;
  RegisterLayout layout;
  llvm::cantFail(layout.AddBank(0, sizeof(PCB)));
  auto add = [&](const std::string &name, uint32_t offset) {
    const auto *reg = description->Find(name);
    assert(reg && "unknown PPC register");
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({0, offset, reg->byte_size});
    llvm::cantFail(layout.Add(reg->id, std::move(location)));
  };
  for (unsigned i = 12; i != 32; ++i) {
    add("r" + std::to_string(i),
        offsetof(PCB, context) + (i - 12) * sizeof(uint32_t));
  }

  add("r1", offsetof(PCB, sp));
  // The 32-bit switch code does not save r2 in pcb_toc.
  add("cr", offsetof(PCB, cr));
  add("lr", offsetof(PCB, lr));
  // savectx saves the continuation PC in the link register.
  add("pc", offsetof(PCB, lr));

  llvm::cantFail(layout.Finalize(std::move(description), arch.GetByteOrder()));
  return layout;
}

} // namespace lldb_private::freebsd_kernel

class RegisterContextFreeBSDKernelCore_ppc
    : public lldb_private::ThreadRegisterContext {
public:
  RegisterContextFreeBSDKernelCore_ppc(lldb_private::Thread &thread,
                                       lldb_private::RegisterLayout layout,
                                       lldb::addr_t pcb_addr);

  llvm::Expected<lldb_private::RegisterValue>
  ReadRegister(lldb_private::RegisterID id) override;

  llvm::Error WriteRegister(lldb_private::RegisterID id,
                            const lldb_private::RegisterValue &value) override;

private:
  lldb::addr_t m_pcb_addr;
};

#endif // LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_PPC_H
