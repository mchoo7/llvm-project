"""Test that we are able to evaluate expressions when the inferior is blocked in a syscall"""

import lldb
from lldbsuite.test.decorators import *
from lldbsuite.test.lldbtest import *
from lldbsuite.test import lldbutil


class ExprSyscallTestCase(TestBase):
    @expectedFailureNetBSD
    def test_setpgid(self):
        self.build()

        # Create a target by the debugger.
        target = self.createTestTarget()
        ready_breakpoint = target.BreakpointCreateBySourceRegex(
            "Wait for debugger to attach", lldb.SBFileSpec("main.cpp")
        )
        self.assertEqual(ready_breakpoint.GetNumLocations(), 1)

        listener = lldb.SBListener("my listener")

        # launch the inferior and don't wait for it to stop
        self.dbg.SetAsync(True)
        error = lldb.SBError()
        flags = target.GetLaunchInfo().GetLaunchFlags()
        process = target.Launch(
            listener,
            None,  # argv
            None,  # envp
            None,  # stdin_path
            None,  # stdout_path
            None,  # stderr_path
            None,  # working directory
            flags,  # launch flags
            False,  # Stop at entry
            error,
        )  # error

        self.assertTrue(process and process.IsValid(), PROCESS_IS_VALID)

        # Finish loader startup before trying to interrupt the sleeping inferior.
        lldbutil.expect_state_changes(
            self, listener, process, [lldb.eStateRunning, lldb.eStateStopped]
        )
        self.assertIsNotNone(
            lldbutil.get_one_thread_stopped_at_breakpoint(process, ready_breakpoint)
        )
        self.assertTrue(target.BreakpointDelete(ready_breakpoint.GetID()))
        self.assertSuccess(process.Continue())
        lldbutil.expect_state_changes(self, listener, process, [lldb.eStateRunning])

        event = lldb.SBEvent()

        # Give the child enough time to reach the syscall,
        # while clearing out all the pending events.
        # The last WaitForEvent call will time out after 2 seconds.
        while listener.WaitForEvent(2, event):
            pass

        # now the process should be running (blocked in the syscall)
        self.assertEqual(process.GetState(), lldb.eStateRunning, "Process is running")

        # send the process a signal
        process.SendAsyncInterrupt()
        lldbutil.expect_state_changes(self, listener, process, [lldb.eStateStopped])

        # as a result the process should stop
        # in all likelihood we have stopped in the middle of the sleep()
        # syscall
        self.assertEqual(process.GetState(), lldb.eStateStopped, PROCESS_STOPPED)
        thread = process.GetSelectedThread()

        # try evaluating a couple of expressions in this state
        self.expect_expr("release_flag = 1", result_value="1")
        func = (
            "GetCurrentProcessId"
            if lldbplatformutil.getPlatform() == "windows"
            else "getpid"
        )
        self.expect_expr(f"(int){func}()", result_value=str(process.GetProcessID()))

        # and run the process to completion
        self.assertSuccess(process.Continue())
        lldbutil.expect_state_changes(
            self, listener, process, [lldb.eStateRunning, lldb.eStateExited]
        )

        self.assertState(process.GetState(), lldb.eStateExited)
        self.assertEqual(process.GetExitStatus(), 0)
