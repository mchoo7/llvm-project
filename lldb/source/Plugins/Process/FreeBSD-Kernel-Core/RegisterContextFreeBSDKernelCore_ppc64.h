//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_PPC64_H
#define LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_PPC64_H

#include "lldb/Register/Descriptions/RegisterDescription_ppc64be.h"
#include "lldb/Register/RegisterLayout.h"
#include "lldb/Target/ThreadRegisterContext.h"
#include "lldb/Utility/ArchSpec.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace lldb_private::freebsd_kernel {

// The prefix saved by cpu_switch and savectx, decoded in target byte order.
struct PPC64PCB {
  uint64_t context[20]; // r12-r31
  uint64_t cr, sp, toc, lr;
};

inline RegisterLayout
CreateRegisterLayoutFreeBSDKernelCore_ppc64be(const ArchSpec &arch,
                                              lldb::addr_t thread_address) {
  assert(arch.GetMachine() == llvm::Triple::ppc64);
  auto description = RegisterDescription_ppc64be::GetShared(
      RegisterDescription_ppc64be::Numbering::ELF);
  using PCB = PPC64PCB;
  RegisterLayout layout;
  llvm::cantFail(layout.AddBank(0, sizeof(PCB)));
  auto add = [&](const std::string &name, uint32_t offset) {
    const auto *reg = description->Find(name);
    assert(reg && "unknown PPC64 register");
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({0, offset, reg->byte_size});
    llvm::cantFail(layout.Add(reg->id, std::move(location)));
  };
  for (unsigned i = 12; i != 32; ++i) {
    // The 64-bit kernel keeps curthread in r13 instead of saving it here.
    if (i == 13)
      continue;

    add("r" + std::to_string(i),
        offsetof(PCB, context) + (i - 12) * sizeof(uint64_t));
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

  add("r1", offsetof(PCB, sp));
  add("r2", offsetof(PCB, toc));
  add("cr", offsetof(PCB, cr));
  add("lr", offsetof(PCB, lr));
  // savectx saves the continuation PC in the link register.
  add("pc", offsetof(PCB, lr));

  llvm::cantFail(layout.Finalize(std::move(description), arch.GetByteOrder()));
  return layout;
}

} // namespace lldb_private::freebsd_kernel

class RegisterContextFreeBSDKernelCore_ppc64
    : public lldb_private::ThreadRegisterContext {
public:
  RegisterContextFreeBSDKernelCore_ppc64(lldb_private::Thread &thread,
                                         lldb_private::RegisterLayout layout,
                                         lldb::addr_t pcb_addr);

  llvm::Expected<lldb_private::RegisterValue>
  ReadRegister(lldb_private::RegisterID id) override;

  llvm::Error WriteRegister(lldb_private::RegisterID id,
                            const lldb_private::RegisterValue &value) override;

private:
  lldb::addr_t m_pcb_addr;
};

#endif // LLDB_SOURCE_PLUGINS_PROCESS_FREEBSDKERNEL_REGISTERCONTEXTFREEBSDKERNELCORE_PPC64_H
