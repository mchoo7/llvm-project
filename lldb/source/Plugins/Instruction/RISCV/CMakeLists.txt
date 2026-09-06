add_lldb_library(lldbPluginInstructionRISCV PLUGIN
  EmulateInstructionRISCV.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbRegisterSupport
    lldbCore
    lldbInterpreter
    lldbSymbol
  )
