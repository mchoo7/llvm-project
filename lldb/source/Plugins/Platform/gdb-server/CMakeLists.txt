add_lldb_library(lldbPluginPlatformGDB PLUGIN
  PlatformRemoteGDBServer.cpp

   LINK_LIBS
    lldbBreakpoint
    lldbCore
    lldbGDBRemoteSupport
    lldbHost
    lldbTarget
    lldbPluginProcessGDBRemote
  )
