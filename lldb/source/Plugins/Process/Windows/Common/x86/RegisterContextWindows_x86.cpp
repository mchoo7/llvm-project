//===-- RegisterContextWindows_x86.cpp ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__i386__) || defined(_M_IX86)

#include "lldb/Host/windows/HostThreadWindows.h"
#include "lldb/Host/windows/windows.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"
#include "lldb/lldb-private-types.h"

#include "ProcessWindowsLog.h"
#include "RegisterContextWindows_x86.h"
#include "RegisterModelWindows_x86.h"
#include "TargetThreadWindows.h"
#include "lldb/Register/Arch/lldb-x86-register-enums.h"

using namespace lldb;
using namespace lldb_private;

namespace {
const RegisterInfo_x86 &RegisterMetadata() {
  static const ArchSpec arch("i686-pc-windows");
  static const RegisterInfo_x86 info(
      arch, CreateWindowsX86RegisterModel(arch, X86RegisterMode::I386,
                                          WindowsX86ContextKind::Frame));
  return info;
}
} // namespace

// Constructors and Destructors
RegisterContextWindows_x86::RegisterContextWindows_x86(
    Thread &thread, uint32_t concrete_frame_idx)
    : RegisterContextWindows(thread, concrete_frame_idx) {}

RegisterContextWindows_x86::~RegisterContextWindows_x86() {}

size_t RegisterContextWindows_x86::GetRegisterCount() {
  return RegisterMetadata().GetRegisterCount();
}

const RegisterInfo *
RegisterContextWindows_x86::GetRegisterInfoAtIndex(size_t reg) {
  const auto &info = RegisterMetadata();
  return reg < info.GetRegisterCount() ? info.GetRegisterInfo() + reg : nullptr;
}

size_t RegisterContextWindows_x86::GetRegisterSetCount() {
  return RegisterMetadata().GetRegisterSetCount();
}

const RegisterSet *RegisterContextWindows_x86::GetRegisterSet(size_t reg_set) {
  return RegisterMetadata().GetRegisterSet(reg_set);
}

bool RegisterContextWindows_x86::ReadRegister(const RegisterInfo *reg_info,
                                              RegisterValue &reg_value) {
  if (!CacheAllRegisterValues())
    return false;

  if (reg_info == nullptr)
    return false;

  uint32_t reg = reg_info->kinds[eRegisterKindLLDB];
  switch (reg) {
  case lldb_eax_i386:
    return ReadRegisterHelper(CONTEXT_INTEGER, "EAX", m_context.Eax, reg_value);
  case lldb_ebx_i386:
    return ReadRegisterHelper(CONTEXT_INTEGER, "EBX", m_context.Ebx, reg_value);
  case lldb_ecx_i386:
    return ReadRegisterHelper(CONTEXT_INTEGER, "ECX", m_context.Ecx, reg_value);
  case lldb_edx_i386:
    return ReadRegisterHelper(CONTEXT_INTEGER, "EDX", m_context.Edx, reg_value);
  case lldb_edi_i386:
    return ReadRegisterHelper(CONTEXT_INTEGER, "EDI", m_context.Edi, reg_value);
  case lldb_esi_i386:
    return ReadRegisterHelper(CONTEXT_INTEGER, "ESI", m_context.Esi, reg_value);
  case lldb_ebp_i386:
    return ReadRegisterHelper(CONTEXT_CONTROL, "EBP", m_context.Ebp, reg_value);
  case lldb_esp_i386:
    return ReadRegisterHelper(CONTEXT_CONTROL, "ESP", m_context.Esp, reg_value);
  case lldb_eip_i386:
    return ReadRegisterHelper(CONTEXT_CONTROL, "EIP", m_context.Eip, reg_value);
  case lldb_eflags_i386:
    return ReadRegisterHelper(CONTEXT_CONTROL, "EFLAGS", m_context.EFlags,
                              reg_value);
  default:
    Log *log = GetLog(WindowsLog::Registers);
    LLDB_LOG(log, "Requested unknown register {0}", reg);
    break;
  }
  return false;
}

bool RegisterContextWindows_x86::WriteRegister(const RegisterInfo *reg_info,
                                               const RegisterValue &reg_value) {
  // Since we cannot only write a single register value to the inferior, we
  // need to make sure our cached copy of the register values are fresh.
  // Otherwise when writing EAX, for example, we may also overwrite some other
  // register with a stale value.
  if (!CacheAllRegisterValues())
    return false;

  Log *log = GetLog(WindowsLog::Registers);
  uint32_t reg = reg_info->kinds[eRegisterKindLLDB];
  switch (reg) {
  case lldb_eax_i386:
    LLDB_LOG(log, "Write value {0:x} to EAX", reg_value.GetAsUInt32());
    m_context.Eax = reg_value.GetAsUInt32();
    break;
  case lldb_ebx_i386:
    LLDB_LOG(log, "Write value {0:x} to EBX", reg_value.GetAsUInt32());
    m_context.Ebx = reg_value.GetAsUInt32();
    break;
  case lldb_ecx_i386:
    LLDB_LOG(log, "Write value {0:x} to ECX", reg_value.GetAsUInt32());
    m_context.Ecx = reg_value.GetAsUInt32();
    break;
  case lldb_edx_i386:
    LLDB_LOG(log, "Write value {0:x} to EDX", reg_value.GetAsUInt32());
    m_context.Edx = reg_value.GetAsUInt32();
    break;
  case lldb_edi_i386:
    LLDB_LOG(log, "Write value {0:x} to EDI", reg_value.GetAsUInt32());
    m_context.Edi = reg_value.GetAsUInt32();
    break;
  case lldb_esi_i386:
    LLDB_LOG(log, "Write value {0:x} to ESI", reg_value.GetAsUInt32());
    m_context.Esi = reg_value.GetAsUInt32();
    break;
  case lldb_ebp_i386:
    LLDB_LOG(log, "Write value {0:x} to EBP", reg_value.GetAsUInt32());
    m_context.Ebp = reg_value.GetAsUInt32();
    break;
  case lldb_esp_i386:
    LLDB_LOG(log, "Write value {0:x} to ESP", reg_value.GetAsUInt32());
    m_context.Esp = reg_value.GetAsUInt32();
    break;
  case lldb_eip_i386:
    LLDB_LOG(log, "Write value {0:x} to EIP", reg_value.GetAsUInt32());
    m_context.Eip = reg_value.GetAsUInt32();
    break;
  case lldb_eflags_i386:
    LLDB_LOG(log, "Write value {0:x} to EFLAGS", reg_value.GetAsUInt32());
    m_context.EFlags = reg_value.GetAsUInt32();
    break;
  default:
    LLDB_LOG(log, "Write value {0:x} to unknown register {1}",
             reg_value.GetAsUInt32(), reg);
    return false;
  }

  // Physically update the registers in the target process.
  return ApplyAllRegisterValues();
}

bool RegisterContextWindows_x86::ReadRegisterHelper(
    DWORD flags_required, const char *reg_name, DWORD value,
    RegisterValue &reg_value) const {
  Log *log = GetLog(WindowsLog::Registers);
  if ((m_context.ContextFlags & flags_required) != flags_required) {
    LLDB_LOG(log, "Thread context doesn't have {0}", reg_name);
    return false;
  }
  LLDB_LOG(log, "Read value {0:x} from {1}", value, reg_name);
  reg_value.SetUInt32(value);
  return true;
}

#endif // defined(__i386__) || defined(_M_IX86)
