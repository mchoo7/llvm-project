lldb_tablegen(TargetProperties.inc -gen-lldb-property-defs
  SOURCE TargetProperties.td
  TARGET LLDBTargetPropertiesGen)

lldb_tablegen(TargetPropertiesEnum.inc -gen-lldb-property-enum-defs
  SOURCE TargetProperties.td
  TARGET LLDBTargetPropertiesEnumGen)

lldb_tablegen(TargetProperties.json -dump-json
  SOURCE TargetProperties.td
  TARGET LLDBTargetPropertiesJsonGen)

# TODO: Add property `NO_PLUGIN_DEPENDENCIES` to lldbTarget
add_lldb_library(lldbTarget
  ABI.cpp
  AssertFrameRecognizer.cpp
  DynamicRegisterInfo.cpp
  CoreFileMemoryRanges.cpp
  ExecutionContext.cpp
  FreeBSDSignals.cpp
  HistoryThread.cpp
  HistoryUnwind.cpp
  InstrumentationRuntime.cpp
  InstrumentationRuntimeStopInfo.cpp
  JITLoader.cpp
  JITLoaderList.cpp
  Language.cpp
  LanguageRuntime.cpp
  LinuxSignals.cpp
  Memory.cpp
  MemoryHistory.cpp
  MemoryRegionInfo.cpp
  MemoryRegionInfoCache.cpp
  MemoryTagMap.cpp
  ModuleCache.cpp
  NetBSDSignals.cpp
  OperatingSystem.cpp
  OpenBSDSignals.cpp
  PathMappingList.cpp
  Platform.cpp
  Process.cpp
  ProcessIOHandler.cpp
  ProcessTrace.cpp
  Queue.cpp
  QueueItem.cpp
  QueueList.cpp
  RegisterContext.cpp
  RegisterContextDummy.cpp
  RegisterContextHistory.cpp
  RegisterContextMemory.cpp
  RegisterContextThreadMemory.cpp
  RegisterContextUnwind.cpp
  RegisterNumber.cpp
  RemoteAwarePlatform.cpp
  ScriptedThreadPlan.cpp
  SyntheticFrameProvider.cpp
  SectionLoadHistory.cpp
  SectionLoadList.cpp
  BorrowedStackFrame.cpp
  StackFrame.cpp
  StackFrameList.cpp
  StackFrameRecognizer.cpp
  StackID.cpp
  Statistics.cpp
  StopInfo.cpp
  StructuredDataPlugin.cpp
  SystemRuntime.cpp
  Target.cpp
  TargetAPIMutex.cpp
  TargetList.cpp
  Thread.cpp
  ThreadCollection.cpp
  ThreadList.cpp
  ThreadMemory.cpp
  ThreadPlan.cpp
  ThreadPlanBase.cpp
  ThreadPlanCallFunction.cpp
  ThreadPlanCallFunctionUsingABI.cpp
  ThreadPlanCallOnFunctionExit.cpp
  ThreadPlanCallUserExpression.cpp
  ThreadPlanRunToAddress.cpp
  ThreadPlanSingleThreadTimeout.cpp
  ThreadPlanShouldStopHere.cpp
  ThreadPlanStepInRange.cpp
  ThreadPlanStepInstruction.cpp
  ThreadPlanStepOut.cpp
  ThreadPlanStepOverBreakpoint.cpp
  ThreadPlanStepOverRange.cpp
  ThreadPlanStepRange.cpp
  ThreadPlanStepThrough.cpp
  ThreadPlanStepUntil.cpp
  ThreadPlanTracer.cpp
  ThreadPlanStack.cpp
  ThreadSpec.cpp
  Trace.cpp
  TraceCursor.cpp
  TraceExporter.cpp
  TraceDumper.cpp
  UnixSignals.cpp
  UnwindAssembly.cpp
  UnwindLLDB.cpp

  ADDITIONAL_HEADER_DIRS
    ${LLDB_INCLUDE_DIR}/lldb/Target
  LINK_COMPONENTS
    Support
    MC
  LINK_LIBS
    lldbBreakpoint
    lldbCore
    lldbExpression
    lldbHost
    lldbInterpreter
    lldbSymbol
    lldbUtility
    lldbValueObject
  )

add_dependencies(lldbTarget
  LLDBTargetPropertiesGen
  LLDBTargetPropertiesEnumGen)
