add_lldb_library(lldbPluginProcessPOSIX
  CrashReason.cpp
  NativeProcessELF.cpp
  ProcessPOSIXLog.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbELFProcessSupport
    lldbUtility
  )
