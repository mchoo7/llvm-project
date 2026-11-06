//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Register/Common/RegisterInfo_ppc64le.h"
#include "RegisterInfo_powerpc_internal.h"
#include "lldb/Register/Arch/lldb-ppc64le-dwarf-eframe-register-enums.h"
#include "lldb/Register/Arch/lldb-ppc64le-register-enums.h"
#include "lldb/lldb-private-types.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Compiler.h"
#include <cassert>
#include <cstddef>
#include <iterator>

using namespace lldb_private;

static llvm::ArrayRef<RegisterInfo> Values8() {
  constexpr uint32_t word_size = 8;
#include "Register/Arch/RegisterDescriptions_ppc64le.inc"
  return values;
}

std::shared_ptr<const RegisterDescription>
RegisterInfo_ppc64le::CreateDescription(const ArchSpec &) {
  static const auto description8 = std::make_shared<RegisterDescription>(
      MakePowerPCDescription(Values8(), true));
  return description8;
}

RegisterInfo_ppc64le::RegisterInfo_ppc64le(const ArchSpec &arch,
                                           RegisterLayout layout)
    : RegisterInfoProvider(arch, CreateDescription(arch), std::move(layout)) {}
