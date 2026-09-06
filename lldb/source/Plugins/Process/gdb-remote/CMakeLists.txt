lldb_tablegen(ProcessGDBRemoteProperties.inc -gen-lldb-property-defs
  SOURCE ProcessGDBRemoteProperties.td
  TARGET LLDBPluginProcessGDBRemotePropertiesGen)

lldb_tablegen(ProcessGDBRemotePropertiesEnum.inc -gen-lldb-property-enum-defs
  SOURCE ProcessGDBRemoteProperties.td
  TARGET LLDBPluginProcessGDBRemotePropertiesEnumGen)

lldb_tablegen(ProcessGDBRemoteProperties.json -dump-json
  SOURCE ProcessGDBRemoteProperties.td
  TARGET LLDBPluginProcessGDBRemotePropertiesJsonGen)

add_lldb_library(lldbGDBRemoteSupport NO_PLUGIN_DEPENDENCIES
  PARTIAL_SOURCES_INTENDED
  GDBRemoteSignals.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbTarget
  ALLOWED_INTERNAL_DEPENDENCIES
    lldbTarget
  )

if(HAVE_LIBCOMPRESSION)
  set(LIBCOMPRESSION compression)
endif()

if(LLVM_ENABLE_ZLIB)
  list(APPEND LLDB_SYSTEM_LIBS ZLIB::ZLIB)
endif()

add_lldb_library(lldbPluginProcessGDBRemote PLUGIN
  PARTIAL_SOURCES_INTENDED
  GDBRemoteClientBase.cpp
  GDBRemoteCommunication.cpp
  GDBRemoteCommunicationClient.cpp
  GDBRemoteCommunicationHistory.cpp
  GDBRemoteCommunicationServer.cpp
  GDBRemoteCommunicationServerCommon.cpp
  GDBRemoteCommunicationServerLLGS.cpp
  GDBRemoteCommunicationServerPlatform.cpp
  LLDBServerAcceleratorPlugin.cpp
  GDBRemoteRegisterContext.cpp
  GDBRemoteRegisterFallback.cpp
  InferiorCallPOSIX.cpp
  ProcessGDBRemote.cpp
  ProcessGDBRemoteLog.cpp
  ThreadGDBRemote.cpp

  LINK_COMPONENTS
    Support
    TargetParser
  LINK_LIBS
    lldbBreakpoint
    lldbCore
    lldbDataFormatters
    lldbHost
    lldbInterpreter
    lldbGDBRemoteSupport
    lldbSymbol
    lldbTarget
    lldbUtility
    ${LLDB_SYSTEM_LIBS}
    ${LIBCOMPRESSION}
  )

add_dependencies(lldbPluginProcessGDBRemote
  LLDBPluginProcessGDBRemotePropertiesGen
  LLDBPluginProcessGDBRemotePropertiesEnumGen)
