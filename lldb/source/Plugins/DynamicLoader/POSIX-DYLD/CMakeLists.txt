add_lldb_library(lldbPluginDynamicLoaderPosixDYLD PLUGIN
  DYLDRendezvous.cpp
  DynamicLoaderPOSIXDYLD.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbELFProcessSupport
    lldbBreakpoint
    lldbCore
    lldbHost
    lldbSymbol
    lldbTarget
    lldbPluginProcessElfCore
  )
