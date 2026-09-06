set_property(DIRECTORY PROPERTY LLDB_PLUGIN_KIND ProcessUtility)

add_lldb_library(lldbRegisterSupport NO_PLUGIN_DEPENDENCIES
  PARTIAL_SOURCES_INTENDED
  RegisterContext_x86.cpp
  RegisterInfoFreeBSD_i386.cpp
  RegisterInfoFreeBSD_powerpc.cpp
  RegisterInfoFreeBSD_x86_64.cpp
  RegisterInfoLinux_i386.cpp
  RegisterInfoLinux_x86_64.cpp
  RegisterInfoLinux_s390x.cpp
  RegisterInfoNetBSD_i386.cpp
  RegisterInfoNetBSD_x86_64.cpp
  RegisterInfoOpenBSD_i386.cpp
  RegisterInfoOpenBSD_x86_64.cpp
  RegisterInfoWindows_i386.cpp
  RegisterInfoWindows_x86_64.cpp
  RegisterTypeDetector_arm64.cpp
  RegisterInfos_x86_64_with_base_shared.cpp
  RegisterInfoCommon_arm.cpp
  RegisterInfoCommon_arm64.cpp
  RegisterInfoCommon_loongarch64.cpp
  RegisterInfoCommon_ppc64le.cpp
  RegisterInfoCommon_ppc64.cpp
  RegisterInfoCommon_riscv32.cpp
  RegisterInfoCommon_riscv64.cpp
  RegisterInfoCommonDynamic_riscv32.cpp

  LINK_COMPONENTS
    Support
    TargetParser
  LINK_LIBS
    lldbUtility
  ALLOWED_INTERNAL_DEPENDENCIES
    lldbUtility
  )

add_lldb_library(lldbPluginProcessUtility
  PARTIAL_SOURCES_INTENDED
  AuxVector.cpp
  LinuxProcMaps.cpp
  MemoryTagManagerAArch64MTE.cpp
  RegisterContextDarwin_arm.cpp
  RegisterContextDarwin_arm64.cpp
  RegisterContextDarwin_riscv32.cpp
  RegisterContextDarwin_x86_64.cpp
  RegisterContextMach_arm.cpp
  RegisterContextMach_x86_64.cpp

  LINK_COMPONENTS
    Support
    TargetParser
  LINK_LIBS
    lldbRegisterSupport
    lldbBreakpoint
    lldbCore
    lldbDataFormatters
    lldbExpression
    lldbHost
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbValueObject
  )
