//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextFreeBSDKernelCore_powerpc.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Thread.h"
#include <vector>

#if defined(__FreeBSD__) && defined(__powerpc__)
#include <sys/types.h>
#include <machine/pcb.h>

using PCBLayout = lldb_private::freebsd_kernel::PowerPCPCB<register_t>;
static_assert(offsetof(struct pcb, pcb_context) ==
              offsetof(PCBLayout, context));
static_assert(offsetof(struct pcb, pcb_cr) == offsetof(PCBLayout, cr));
static_assert(offsetof(struct pcb, pcb_sp) == offsetof(PCBLayout, sp));
static_assert(offsetof(struct pcb, pcb_toc) == offsetof(PCBLayout, toc));
static_assert(offsetof(struct pcb, pcb_lr) == offsetof(PCBLayout, lr));
#endif

using namespace lldb;
using namespace lldb_private;

RegisterContextFreeBSDKernelCore_powerpc::
    RegisterContextFreeBSDKernelCore_powerpc(Thread &thread,
                                             RegisterLayout layout,
                                             addr_t pcb_addr)
    : ThreadRegisterContext(thread, 0, std::move(layout)),
      m_pcb_addr(pcb_addr) {}

llvm::Expected<RegisterValue>
RegisterContextFreeBSDKernelCore_powerpc::ReadRegister(RegisterID id) {
  auto required = GetLayout().GetRequiredBanks(id);
  if (!required)
    return required.takeError();
  if (required->empty())
    return ReadBankRegister(id, {});
  if (m_pcb_addr == LLDB_INVALID_ADDRESS)
    return llvm::createStringError("register value is unavailable");
  std::vector<uint8_t> pcb(GetBankSize(0));
  Status error;
  size_t read = m_thread.GetProcess()->ReadMemory(m_pcb_addr, pcb.data(),
                                                  pcb.size(), error);
  if (read != pcb.size())
    return llvm::createStringError("register value is unavailable");
  return ReadBankRegister(id, RegisterData{0, pcb});
}

llvm::Error RegisterContextFreeBSDKernelCore_powerpc::WriteRegister(
    RegisterID id, const RegisterValue &value) {
  return llvm::createStringError("register write is unavailable");
}
