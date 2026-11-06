//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextMinidump_x86.h"
#include "RegisterContextMinidump_x86_32.h"
#include "RegisterContextMinidump_x86_64.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Endian.h"
#include <cstddef>
#include <set>
using namespace lldb_private;
using namespace lldb_private::minidump;
namespace {
struct Field {
  const char *name;
  uint32_t size;
  uint32_t offset;
  uint32_t flags;
};
#define FIELD(name, member, flag)                                              \
  {name, sizeof(((Context *)nullptr)->member), offsetof(Context, member),      \
   static_cast<uint32_t>(Flags::flag)}
namespace format32 {
using Context = MinidumpContext_x86_32;
using Flags = MinidumpContext_x86_32_Flags;
const Field fields[] = {
    FIELD("ebp", ebp, Control), FIELD("eip", eip, Control),
    FIELD("cs", cs, Control),   FIELD("eflags", eflags, Control),
    FIELD("esp", esp, Control), FIELD("ss", ss, Control),
    FIELD("eax", eax, Integer), FIELD("ecx", ecx, Integer),
    FIELD("edx", edx, Integer), FIELD("ebx", ebx, Integer),
    FIELD("esi", esi, Integer), FIELD("edi", edi, Integer),
    FIELD("ds", ds, Segments),  FIELD("es", es, Segments),
    FIELD("fs", fs, Segments),  FIELD("gs", gs, Segments),
};
} // namespace format32
namespace format64 {
using Context = MinidumpContext_x86_64;
using Flags = MinidumpContext_x86_64_Flags;
const Field fields[] = {
    FIELD("cs", cs, Control),
    FIELD("ss", ss, Control),
    FIELD("rflags", eflags, Control),
    FIELD("rsp", rsp, Control),
    FIELD("rip", rip, Control),
    FIELD("rax", rax, Integer),
    FIELD("rcx", rcx, Integer),
    FIELD("rdx", rdx, Integer),
    FIELD("rbx", rbx, Integer),
    FIELD("rbp", rbp, Integer),
    FIELD("rsi", rsi, Integer),
    FIELD("rdi", rdi, Integer),
    FIELD("r8", r8, Integer),
    FIELD("r9", r9, Integer),
    FIELD("r10", r10, Integer),
    FIELD("r11", r11, Integer),
    FIELD("r12", r12, Integer),
    FIELD("r13", r13, Integer),
    FIELD("r14", r14, Integer),
    FIELD("r15", r15, Integer),
    FIELD("ds", ds, Segments),
    FIELD("es", es, Segments),
    FIELD("fs", fs, Segments),
    FIELD("gs", gs, Segments),
    FIELD("fs_base", fs_base, LLDBSpecific),
    FIELD("gs_base", gs_base, LLDBSpecific),
};
} // namespace format64
#undef FIELD
llvm::ArrayRef<Field> Fields(const ArchSpec &arch) {
  return arch.GetMachine() == llvm::Triple::x86
             ? llvm::ArrayRef(format32::fields)
             : llvm::ArrayRef(format64::fields);
}
size_t ContextSize(const ArchSpec &arch) {
  return arch.GetMachine() == llvm::Triple::x86
             ? sizeof(MinidumpContext_x86_32)
             : sizeof(MinidumpContext_x86_64);
}
} // namespace
RegisterModel
lldb_private::minidump::CreateMinidumpX86RegisterModel(const ArchSpec &arch) {
  X86RegisterProfile profile;
  profile.avx = profile.mpx = profile.debug = false;
  auto description = RegisterInfo_x86::CreateDescription(
      arch, arch.GetMachine() == llvm::Triple::x86_64,
      arch.GetTriple().isOSWindows() ? X86RegisterABI::Windows
                                     : X86RegisterABI::SystemV,
      X86RegisterMode::Target, profile);
  RegisterLayout layout(lldb::eByteOrderLittle);
  llvm::cantFail(layout.AddBank(0, ContextSize(arch)));
  std::map<RegisterID, RegisterLocation> locations;
  for (const auto &field : Fields(arch)) {
    const auto *reg = description->Find(field.name);
    assert(reg && reg->byte_size >= field.size);
    RegisterLocation location;
    location.kind = RegisterLocation::Stored;
    location.pieces.push_back({0, field.offset, field.size});
    location.zero_fill = field.size < reg->byte_size;
    locations.emplace(reg->id, std::move(location));
  }
  for (size_t pass = 0; pass < description->GetRegisters().size(); ++pass)
    for (const auto &reg : description->GetRegisters()) {
      if (locations.count(reg.id) || reg.value_registers.size() != 1)
        continue;
      auto parent = locations.find(reg.value_registers.front());
      if (parent == locations.end() || parent->second.zero_fill)
        continue;
      const auto &piece = parent->second.pieces.front();
      if (reg.value_byte_offset + reg.byte_size > piece.byte_size)
        continue;
      RegisterLocation location;
      location.kind = RegisterLocation::Stored;
      location.pieces.push_back(
          {0, piece.byte_offset + reg.value_byte_offset, reg.byte_size});
      locations.emplace(reg.id, std::move(location));
    }
  for (auto &[id, location] : locations)
    llvm::cantFail(layout.Add(id, std::move(location)));
  llvm::cantFail(layout.Validate(*description));
  return {std::move(description), std::move(layout)};
}
llvm::Expected<RegisterValue> lldb_private::minidump::ReadMinidumpX86Register(
    const RegisterInfoProvider &info, llvm::ArrayRef<uint8_t> context,
    const RegisterInfo &reg) {
  const auto &arch = info.GetTargetArchitecture();
  if (context.size() < ContextSize(arch))
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "truncated minidump register context");
  bool is32 = arch.GetMachine() == llvm::Triple::x86;
  uint32_t flags_offset = is32
                              ? offsetof(MinidumpContext_x86_32, context_flags)
                              : offsetof(MinidumpContext_x86_64, context_flags);
  uint32_t cpu_flag =
      is32 ? static_cast<uint32_t>(MinidumpContext_x86_32_Flags::x86_32_Flag)
           : static_cast<uint32_t>(MinidumpContext_x86_64_Flags::x86_64_Flag);
  uint32_t flags =
      llvm::support::endian::read32le(context.data() + flags_offset);
  auto *descriptor = info.GetDescription().Find(reg.name);
  std::set<RegisterID> seen;
  while (descriptor && seen.insert(descriptor->id).second) {
    for (const auto &field : Fields(arch))
      if (descriptor->name == field.name) {
        uint32_t required = cpu_flag | field.flags;
        if ((flags & required) != required)
          return llvm::createStringError(
              llvm::inconvertibleErrorCode(),
              "register set is absent from minidump");
        return info.ReadRegister(reg, {{0, context}});
      }
    if (descriptor->value_registers.size() != 1)
      break;
    descriptor =
        info.GetDescription().Find(descriptor->value_registers.front());
  }
  return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                 "register is unavailable in minidump");
}
RegisterContextMinidump_x86::RegisterContextMinidump_x86(
    Thread &thread, const ArchSpec &arch, llvm::ArrayRef<uint8_t> context)
    : RegisterContext(thread, 0),
      m_info(arch, CreateMinidumpX86RegisterModel(arch)),
      m_context(context.begin(), context.end()) {}
bool RegisterContextMinidump_x86::ReadRegister(const RegisterInfo *reg,
                                               RegisterValue &value) {
  if (!reg)
    return false;
  auto result = ReadMinidumpX86Register(m_info, m_context, *reg);
  if (!result) {
    llvm::consumeError(result.takeError());
    return false;
  }
  value = std::move(*result);
  return true;
}
