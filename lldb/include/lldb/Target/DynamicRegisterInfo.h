//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_TARGET_DYNAMICREGISTERINFO_H
#define LLDB_TARGET_DYNAMICREGISTERINFO_H
#include "lldb/Register/RegisterDescriptionBuilder.h"
#include "lldb/Utility/StructuredData.h"
namespace lldb_private {
/// Input-format and presentation adapter for dynamic register definitions.
class DynamicRegisterInfo : public RegisterDescriptionBuilder {
public:
  using RegisterDescriptionBuilder::SetRegisterInfo;
  static std::unique_ptr<DynamicRegisterInfo>
  Create(const StructuredData::Dictionary &dict, const ArchSpec &arch);
  size_t SetRegisterInfo(const StructuredData::Dictionary &dict,
                         const ArchSpec &arch);
  void Dump(Stream &stream) const;

protected:
  llvm::Expected<uint32_t> ByteOffsetFromSlice(uint32_t index,
                                               llvm::StringRef slice_str,
                                               lldb::ByteOrder byte_order);
  llvm::Expected<uint32_t> ByteOffsetFromComposite(
      uint32_t index, lldb_private::StructuredData::Array &composite_reg_list,
      lldb::ByteOrder byte_order);
  llvm::Expected<uint32_t> ByteOffsetFromRegInfoDict(
      uint32_t index, lldb_private::StructuredData::Dictionary &reg_info_dict,
      lldb::ByteOrder byte_order);
};
} // namespace lldb_private
#endif
