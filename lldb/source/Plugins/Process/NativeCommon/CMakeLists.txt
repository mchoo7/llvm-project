add_lldb_library(lldbNativeProcessSupport NO_PLUGIN_DEPENDENCIES
  NativeProcessSoftwareSingleStep.cpp
  NativeRegisterContextDBReg.cpp
  NativeRegisterContextDBReg_arm.cpp
  NativeRegisterContextDBReg_arm64.cpp
  NativeRegisterContextDBReg_loongarch.cpp
  NativeRegisterContextDBReg_x86.cpp
  NativeRegisterContextRegisterInfo.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbCore
    lldbHost
    lldbRegisterSupport
    lldbUtility
  ALLOWED_INTERNAL_DEPENDENCIES
    lldbCore
    lldbHost
    lldbRegisterSupport
    lldbUtility
  )
