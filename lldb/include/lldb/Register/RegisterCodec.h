//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_REGISTER_REGISTERCODEC_H
#define LLDB_REGISTER_REGISTERCODEC_H

#include "lldb/Register/RegisterLayout.h"
#include "lldb/Utility/RegisterValue.h"

namespace lldb_private {

struct RegisterData {
  RegisterBankID bank;
  llvm::ArrayRef<uint8_t> bytes;
};

struct MutableRegisterData {
  RegisterBankID bank;
  llvm::MutableArrayRef<uint8_t> bytes;
};

/// Buffer operations only: no callbacks, process memory access or native APIs.
class RegisterCodec {
public:
  static llvm::Expected<RegisterValue>
  Read(const RegisterDescription &description, const RegisterLayout &layout,
       RegisterID id, llvm::ArrayRef<RegisterData> banks);

  /// Validate every piece before modifying any bytes.
  static llvm::Error Write(const RegisterDescription &description,
                           const RegisterLayout &layout, RegisterID id,
                           const RegisterValue &value,
                           llvm::ArrayRef<MutableRegisterData> banks);
};

} // namespace lldb_private

#endif
