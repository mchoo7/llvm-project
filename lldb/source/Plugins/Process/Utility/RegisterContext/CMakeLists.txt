add_lldb_library(lldbProcessContextSupport NO_PLUGIN_DEPENDENCIES
  Darwin/RegisterContextDarwin_arm.cpp
  Darwin/RegisterContextDarwin_arm64.cpp
  Darwin/RegisterContextDarwin_riscv32.cpp
  Darwin/RegisterContextDarwin_x86_64.cpp
  Darwin/RegisterContextMach_arm.cpp
  Darwin/RegisterContextMach_x86_64.cpp
  POSIX/RegisterContextPOSIX_arm.cpp
  POSIX/RegisterContextPOSIX_arm64.cpp
  POSIX/RegisterContextPOSIX_loongarch64.cpp
  POSIX/RegisterContextPOSIX_powerpc.cpp
  POSIX/RegisterContextPOSIX_ppc64le.cpp
  POSIX/RegisterContextPOSIX_riscv32.cpp
  POSIX/RegisterContextPOSIX_riscv64.cpp
  POSIX/RegisterContextPOSIX_s390x.cpp
  POSIX/RegisterContextPOSIX_x86.cpp

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
