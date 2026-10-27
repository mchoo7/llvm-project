//===-- PlatformFreeBSD.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "PlatformFreeBSD.h"
#include "lldb/Host/Config.h"

#include <cstdio>
#if LLDB_ENABLE_POSIX
#include <sys/utsname.h>
#endif

#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Breakpoint/BreakpointSite.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Symbol/UnwindPlan.h"
#include "Utility/ARM64_DWARF_Registers.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/FileSpec.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/State.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/StreamString.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/Support/Endian.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/Triple.h"

// Define these constants from FreeBSD mman.h for use when targeting remote
// FreeBSD systems even when host has different values.
#define MAP_PRIVATE 0x0002
#define MAP_ANON 0x1000

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::platform_freebsd;

LLDB_PLUGIN_DEFINE(PlatformFreeBSD)

static uint32_t g_initialize_count = 0;


PlatformSP PlatformFreeBSD::CreateInstance(bool force, const ArchSpec *arch) {
  Log *log = GetLog(LLDBLog::Platform);
  LLDB_LOG(log, "force = {0}, arch=({1}, {2})", force,
           arch ? arch->GetArchitectureName() : "<null>",
           arch ? arch->GetTriple().getTriple() : "<null>");

  bool create = force;
  if (!create && arch && arch->IsValid()) {
    const llvm::Triple &triple = arch->GetTriple();
    switch (triple.getOS()) {
    case llvm::Triple::FreeBSD:
      create = true;
      break;

#if defined(__FreeBSD__)
    // Only accept "unknown" for the OS if the host is BSD and it "unknown"
    // wasn't specified (it was just returned because it was NOT specified)
    case llvm::Triple::OSType::UnknownOS:
      create = !arch->TripleOSWasSpecified();
      break;
#endif
    default:
      break;
    }
  }
  LLDB_LOG(log, "create = {0}", create);
  if (create) {
    return PlatformSP(new PlatformFreeBSD(false));
  }
  return PlatformSP();
}

llvm::StringRef PlatformFreeBSD::GetPluginDescriptionStatic(bool is_host) {
  if (is_host)
    return "Local FreeBSD user platform plug-in.";
  return "Remote FreeBSD user platform plug-in.";
}

void PlatformFreeBSD::Initialize() {
  Platform::Initialize();

  if (g_initialize_count++ == 0) {
#if defined(__FreeBSD__)
    PlatformSP default_platform_sp(new PlatformFreeBSD(true));
    default_platform_sp->SetSystemArchitecture(HostInfo::GetArchitecture());
    Platform::SetHostPlatform(default_platform_sp);
#endif
    PluginManager::RegisterPlugin(
        PlatformFreeBSD::GetPluginNameStatic(false),
        PlatformFreeBSD::GetPluginDescriptionStatic(false),
        PlatformFreeBSD::CreateInstance, nullptr);
  }
}

void PlatformFreeBSD::Terminate() {
  if (g_initialize_count > 0) {
    if (--g_initialize_count == 0) {
      PluginManager::UnregisterPlugin(PlatformFreeBSD::CreateInstance);
    }
  }

  PlatformPOSIX::Terminate();
}

/// Default Constructor
PlatformFreeBSD::PlatformFreeBSD(bool is_host)
    : PlatformPOSIX(is_host) // This is the local host platform
{
  if (is_host) {
    ArchSpec hostArch = HostInfo::GetArchitecture(HostInfo::eArchKindDefault);
    m_supported_architectures.push_back(hostArch);
    if (hostArch.GetTriple().isArch64Bit()) {
      m_supported_architectures.push_back(
          HostInfo::GetArchitecture(HostInfo::eArchKind32));
    }
  } else {
    m_supported_architectures = CreateArchList(
        {llvm::Triple::x86_64, llvm::Triple::x86, llvm::Triple::aarch64,
         llvm::Triple::arm, llvm::Triple::ppc64, llvm::Triple::ppc},
        llvm::Triple::FreeBSD);
  }
}

std::vector<ArchSpec>
PlatformFreeBSD::GetSupportedArchitectures(const ArchSpec &process_host_arch) {
  if (m_remote_platform_sp)
    return m_remote_platform_sp->GetSupportedArchitectures(process_host_arch);
  return m_supported_architectures;
}

void PlatformFreeBSD::GetStatus(Stream &strm) {
  Platform::GetStatus(strm);

#if LLDB_ENABLE_POSIX
  // Display local kernel information only when we are running in host mode.
  // Otherwise, we would end up printing non-FreeBSD information (when running
  // on Mac OS for example).
  if (IsHost()) {
    struct utsname un;

    if (uname(&un))
      return;

    strm.Printf("    Kernel: %s\n", un.sysname);
    strm.Printf("   Release: %s\n", un.release);
    strm.Printf("   Version: %s\n", un.version);
  }
#endif
}

bool PlatformFreeBSD::CanDebugProcess() {
  if (IsHost()) {
    return true;
  } else {
    // If we're connected, we can debug.
    return IsConnected();
  }
}

void PlatformFreeBSD::CalculateTrapHandlerSymbolNames() {
  m_trap_handlers.push_back("_sigtramp");
}

llvm::Expected<addr_t>
PlatformFreeBSD::ResolveIndirectFunction(Process &process,
                                        const Address &resolver) {
  if (process.GetTarget().GetArchitecture().GetMachine() != llvm::Triple::aarch64)
    return Platform::ResolveIndirectFunction(process, resolver);

  // This is a userland ABI. Prefer rtld's ELF ABI tag to the kernel version,
  // since the inferior may use an older userland on a newer kernel.
  llvm::VersionTuple version = GetOSVersion(&process);
  for (ModuleSP module : process.GetTarget().GetImages().Modules()) {
    if (module->GetFileSpec().GetFilename() == "ld-elf.so.1") {
      auto userland_version = module->GetArchitecture().GetTriple().getOSVersion();
      if (!userland_version.empty())
        version = userland_version;
      break;
    }
  }
  // Before FreeBSD 15.1, all eight resolver arguments were reserved zeros.
  if (version < llvm::VersionTuple(15, 1)) {
    addr_t result = LLDB_INVALID_ADDRESS;
    if (!process.CallFunctionReturnPointer(
            &resolver, {0, 0, 0, 0, 0, 0, 0, 0}, result))
      return llvm::createStringError("IFUNC resolver call failed");
    return result;
  }

  // FreeBSD arm64 passes HWCAP, an __ifunc_arg_t pointer, and six reserved
  // zero arguments. A no-argument call leaves stale registers that can make
  // libc select an implementation using instructions unsupported by the CPU.
  DataExtractor auxv = process.GetAuxvData();
  if (!auxv.GetByteSize())
    return llvm::createStringError("No auxiliary vector for IFUNC capabilities");
  uint64_t capabilities[4] = {};
  for (offset_t offset = 0; auxv.ValidOffsetForDataOfSize(offset, 16);) {
    uint64_t type = auxv.GetU64(&offset);
    uint64_t value = auxv.GetU64(&offset);
    if (type == 0)
      break;
    switch (type) {
    case 25: // AT_HWCAP
      capabilities[0] = value;
      break;
    case 26: // AT_HWCAP2
      capabilities[1] = value;
      break;
    case 38: // AT_HWCAP3
      capabilities[2] = value;
      break;
    case 39: // AT_HWCAP4
      capabilities[3] = value;
      break;
    }
  }
  capabilities[0] |= uint64_t(1) << 62; // _IFUNC_ARG_HWCAP

  // Encode __ifunc_arg_t using the target layout, independent of host headers.
  uint8_t data[40];
  llvm::support::endian::write64le(data, sizeof(data));
  for (unsigned i = 0; i != 4; ++i)
    llvm::support::endian::write64le(data + 8 * (i + 1), capabilities[i]);

  Status error;
  addr_t args_addr = process.AllocateMemory(
      sizeof(data), ePermissionsReadable | ePermissionsWritable, error);
  if (args_addr == LLDB_INVALID_ADDRESS)
    return error.ToError();
  auto cleanup = llvm::scope_exit([&] { process.DeallocateMemory(args_addr); });
  if (process.WriteMemory(args_addr, data, sizeof(data), error) != sizeof(data))
    return llvm::createStringError("Unable to write IFUNC resolver arguments");
  addr_t result = LLDB_INVALID_ADDRESS;
  if (!process.CallFunctionReturnPointer(
          &resolver, {capabilities[0], args_addr, 0, 0, 0, 0, 0, 0}, result))
    return llvm::createStringError("IFUNC resolver call failed");
  return result;
}

lldb::UnwindPlanSP PlatformFreeBSD::GetTrapHandlerUnwindPlanForAddress(
    const ArchSpec &arch, Process &process, addr_t pc) {
  if (arch.GetMachine() != llvm::Triple::aarch64 || pc < 4 || (pc & 3))
    return {};

  // FreeBSD maps sigcode in a shared page without an ELF object or symbols.
  // Recognize the return address from its call to the user signal handler:
  //   blr x8
  //   mov x0, sp           <- pc while the handler is on the stack
  //   add x0, x0, #SF_UC
  //   mov x8, #SYS_sigreturn
  //   svc #0
  uint8_t code[20];
  Status error;
  if (process.ReadMemory(pc - 4, code, sizeof(code), error) != sizeof(code))
    return {};
  auto instruction = [&](unsigned index) {
    return llvm::support::endian::read32le(code + 4 * index);
  };
  if (instruction(0) != 0xd63f0100 || instruction(1) != 0x910003e0 ||
      (instruction(2) & ~0x003ffc00U) != 0x91000000 ||
      instruction(3) != (0xd2800008U | (417U << 5)) ||
      instruction(4) != 0xd4000001)
    return {};

  // SF_UC is encoded in the add instruction. The ucontext begins with the
  // 16-byte signal mask, followed by mcontext's gpregs: x0-x29, lr, sp, elr,
  // spsr. Use target ABI offsets rather than host FreeBSD headers.
  const uint32_t gp_offset = ((instruction(2) >> 10) & 0xfff) + 16;
  UnwindPlan::Row row;
  row.GetCFAValue().SetIsRegisterPlusOffset(arm64_dwarf::sp, gp_offset);
  row.SetUnspecifiedRegistersAreUndefined(true);
  for (unsigned reg = arm64_dwarf::x0; reg <= arm64_dwarf::pc; ++reg)
    row.SetRegisterLocationToAtCFAPlusOffset(reg, reg * 8, false);

  auto plan = std::make_shared<UnwindPlan>(eRegisterKindDWARF);
  plan->AppendRow(std::move(row));
  plan->SetSourceName("FreeBSD arm64 signal context");
  plan->SetSourcedFromCompiler(eLazyBoolYes);
  plan->SetUnwindPlanValidAtAllInstructions(eLazyBoolYes);
  plan->SetUnwindPlanForSignalTrap(eLazyBoolYes);
  return plan;
}

MmapArgList PlatformFreeBSD::GetMmapArgumentList(const ArchSpec &arch,
                                                 addr_t addr, addr_t length,
                                                 unsigned prot, unsigned flags,
                                                 addr_t fd, addr_t offset) {
  uint64_t flags_platform = 0;

  if (flags & eMmapFlagsPrivate)
    flags_platform |= MAP_PRIVATE;
  if (flags & eMmapFlagsAnon)
    flags_platform |= MAP_ANON;

  MmapArgList args({addr, length, prot, flags_platform, fd, offset});
  if (arch.GetTriple().getArch() == llvm::Triple::x86)
    args.push_back(0);
  return args;
}

CompilerType PlatformFreeBSD::GetSiginfoType(const llvm::Triple &triple) {
  {
    std::lock_guard<std::mutex> guard(m_mutex);
    if (!m_type_system)
      m_type_system = std::make_shared<TypeSystemClang>("siginfo", triple);
  }
  TypeSystemClang *ast = m_type_system.get();

  // generic types
  CompilerType int_type = ast->GetBasicType(eBasicTypeInt);
  CompilerType uint_type = ast->GetBasicType(eBasicTypeUnsignedInt);
  CompilerType long_type = ast->GetBasicType(eBasicTypeLong);
  CompilerType voidp_type = ast->GetBasicType(eBasicTypeVoid).GetPointerType();

  // platform-specific types
  CompilerType &pid_type = int_type;
  CompilerType &uid_type = uint_type;

  CompilerType sigval_type = ast->CreateRecordType(
      nullptr, OptionalClangModuleID(), "__lldb_sigval_t",
      llvm::to_underlying(clang::TagTypeKind::Union), lldb::eLanguageTypeC);
  ast->StartTagDeclarationDefinition(sigval_type);
  ast->AddFieldToRecordType(sigval_type, "sival_int", int_type, 0);
  ast->AddFieldToRecordType(sigval_type, "sival_ptr", voidp_type, 0);
  ast->CompleteTagDeclarationDefinition(sigval_type);

  // siginfo_t
  CompilerType siginfo_type = ast->CreateRecordType(
      nullptr, OptionalClangModuleID(), "__lldb_siginfo_t",
      llvm::to_underlying(clang::TagTypeKind::Struct), lldb::eLanguageTypeC);
  ast->StartTagDeclarationDefinition(siginfo_type);
  ast->AddFieldToRecordType(siginfo_type, "si_signo", int_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_errno", int_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_code", int_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_pid", pid_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_uid", uid_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_status", int_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_addr", voidp_type, 0);
  ast->AddFieldToRecordType(siginfo_type, "si_value", sigval_type, 0);

  // union used to hold the signal data
  CompilerType union_type = ast->CreateRecordType(
      nullptr, OptionalClangModuleID(), "",
      llvm::to_underlying(clang::TagTypeKind::Union), lldb::eLanguageTypeC);
  ast->StartTagDeclarationDefinition(union_type);

  ast->AddFieldToRecordType(
      union_type, "_fault",
      ast->CreateStructForIdentifier(llvm::StringRef(),
                                     {
                                         {"_trapno", int_type},
                                     }),
      0);

  ast->AddFieldToRecordType(
      union_type, "_timer",
      ast->CreateStructForIdentifier(llvm::StringRef(),
                                     {
                                         {"_timerid", int_type},
                                         {"_overrun", int_type},
                                     }),
      0);

  ast->AddFieldToRecordType(
      union_type, "_mesgq",
      ast->CreateStructForIdentifier(llvm::StringRef(),
                                     {
                                         {"_mqd", int_type},
                                     }),
      0);

  ast->AddFieldToRecordType(
      union_type, "_poll",
      ast->CreateStructForIdentifier(llvm::StringRef(),
                                     {
                                         {"_band", long_type},
                                     }),
      0);

  ast->CompleteTagDeclarationDefinition(union_type);
  ast->AddFieldToRecordType(siginfo_type, "_reason", union_type, 0);

  ast->CompleteTagDeclarationDefinition(siginfo_type);
  return siginfo_type;
}
