add_lldb_library(lldbPluginProcessAIX
  NativeProcessAIX.cpp
  NativeThreadAIX.cpp
  NativeRegisterContextAIX.cpp
  NativeRegisterContextAIX_ppc64.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbNativeProcessSupport
    lldbRegisterSupport
    lldbCore
    lldbHost
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginProcessPOSIX
  )

target_compile_definitions(lldbPluginProcessAIX PRIVATE "-D_ALL_SOURCE")
