add_lldb_library(lldbELFProcessSupport NO_PLUGIN_DEPENDENCIES
  AuxVector.cpp
  LinuxProcMaps.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbTarget
    lldbUtility
  ALLOWED_INTERNAL_DEPENDENCIES
    lldbTarget
    lldbUtility
  )
