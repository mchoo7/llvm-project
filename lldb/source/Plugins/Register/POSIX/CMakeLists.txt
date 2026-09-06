add_lldb_library(lldbPluginRegisterPOSIX NO_PLUGIN_DEPENDENCIES
  RegisterContextPOSIX_arm.cpp
  RegisterContextPOSIX_arm64.cpp
  RegisterContextPOSIX_loongarch64.cpp
  RegisterContextPOSIX_powerpc.cpp
  RegisterContextPOSIX_ppc64le.cpp
  RegisterContextPOSIX_riscv32.cpp
  RegisterContextPOSIX_riscv64.cpp
  RegisterContextPOSIX_s390x.cpp
  RegisterContextPOSIX_x86.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbRegister
    lldbTarget
    lldbUtility
  ALLOWED_INTERNAL_DEPENDENCIES
    lldbRegister
    lldbTarget
    lldbUtility
  )
