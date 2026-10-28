"""
Make sure that we handle an expression on a thread, if
the thread exits while the expression is running.
"""

import lldb
from lldbsuite.test.decorators import *
import lldbsuite.test.lldbutil as lldbutil
from lldbsuite.test.lldbtest import *


@requireThreadSupport
@skipIfAsan
class TestExitDuringExpression(TestBase):
    NO_DEBUG_INFO_TESTCASE = True

    @skipIfWindows
    @skipIf(oslist=["linux"], archs=["arm$", "aarch64"], bugnumber="llvm.org/pr48414")
    @skipIf(oslist=["freebsd"], bugnumber="llvm.org/pr48414")
    @expectedFailureNetBSD
    def test_exit_before_one_thread_unwind(self):
        """Test the case where we exit within the one thread timeout"""
        self.exiting_expression_test(True, True)

    @skipIfWindows
    @skipIf(oslist=["linux"], archs=["arm$", "aarch64"], bugnumber="llvm.org/pr48414")
    @skipIf(oslist=["freebsd"], bugnumber="llvm.org/pr48414")
    @expectedFailureNetBSD
    def test_exit_before_one_thread_no_unwind(self):
        """Test the case where we exit within the one thread timeout"""
        self.exiting_expression_test(True, False)

    @skipIfWindows
    def test_exit_after_one_thread_unwind(self):
        """Test the case where we exit within the one thread timeout"""
        self.exiting_expression_test(False, True)

    @skipIfWindows
    def test_exit_after_one_thread_no_unwind(self):
        """Test the case where we exit within the one thread timeout"""
        self.exiting_expression_test(False, False)

    @skipIfWindows
    def test_process_exit_unwind(self):
        self.process_exit_test(True)

    @skipIfWindows
    def test_process_exit_no_unwind(self):
        self.process_exit_test(False)

    def process_exit_test(self, unwind):
        _, process, thread, _ = lldbutil.run_to_source_breakpoint(
            self, "Break here and cause the thread to exit", self.main_source_file
        )
        options = lldb.SBExpressionOptions()
        options.SetUnwindOnError(unwind)
        options.SetTimeoutInMicroSeconds(30_000_000)
        result = thread.frames[0].EvaluateExpression("exit_process()", options)
        self.assertTrue(result.GetError().Fail(), "The expression cannot return")
        self.assertState(process.GetState(), lldb.eStateExited)

    def setUp(self):
        TestBase.setUp(self)
        self.main_source_file = lldb.SBFileSpec("main.c")
        self.build()

    def exiting_expression_test(self, before_one_thread_timeout, unwind):
        """function_to_call sleeps for g_timeout microseconds, then calls pthread_exit.
        This test calls function_to_call with an overall timeout of 500
        microseconds, and a one_thread_timeout as passed in.
        It also sets unwind_on_exit for the call to the unwind passed in.
        This allows you to have the thread exit either before the one thread
        timeout is passed."""

        (target, process, thread, bkpt) = lldbutil.run_to_source_breakpoint(
            self, "Break here and cause the thread to exit", self.main_source_file
        )

        # Stop the surviving thread once join completes so it cannot reach the
        # final breakpoint before expression evaluation notices the thread exit.
        joined_bkpt = target.BreakpointCreateBySourceRegex(
            "Stop after joining the expression thread", self.main_source_file
        )
        self.assertEqual(joined_bkpt.GetNumLocations(), 1)
        # We'll continue to this breakpoint after running our expression:
        return_bkpt = target.BreakpointCreateBySourceRegex(
            "Break here to make sure the thread exited", self.main_source_file
        )
        frame = thread.frames[0]
        tid = thread.GetThreadID()
        # Find the timeout:
        var_options = lldb.SBVariablesOptions()
        var_options.SetIncludeArguments(False)
        var_options.SetIncludeLocals(False)
        var_options.SetIncludeStatics(True)

        value_list = frame.GetVariables(var_options)
        g_timeout = value_list.GetFirstValueByName("g_timeout")
        self.assertTrue(g_timeout.IsValid(), "Found g_timeout")

        error = lldb.SBError()
        timeout_value = g_timeout.GetValueAsUnsigned(error)
        self.assertSuccess(error, "Couldn't get timeout value")

        one_thread_timeout = 0
        if before_one_thread_timeout:
            one_thread_timeout = timeout_value * 2
        else:
            one_thread_timeout = int(timeout_value / 2)

        options = lldb.SBExpressionOptions()
        options.SetUnwindOnError(unwind)
        # This breakpoint supplies the stop where LLDB observes the thread
        # exit. Ignoring it would let main run through the final breakpoint too.
        options.SetIgnoreBreakpoints(False)
        options.SetOneThreadTimeoutInMicroSeconds(one_thread_timeout)
        # Keep the single-thread transition tied to the inferior sleep, but
        # allow scheduler and debugger overhead when waiting for thread exit.
        options.SetTimeoutInMicroSeconds(max(4 * timeout_value, 30_000_000))

        # The handoff is on the surviving thread, which has no expression call
        # plan. Its breakpoints follow the process setting rather than options.
        setting = "target.process.ignore-breakpoints-in-expressions"
        saved_setting = self.dbg.GetInternalVariableValue(
            setting, self.dbg.GetInstanceName()
        ).GetStringAtIndex(0)
        self.runCmd("settings set %s false" % setting)
        try:
            result = frame.EvaluateExpression("function_to_call()", options)
        finally:
            self.runCmd("settings set %s %s" % (setting, saved_setting))

        # Make sure the thread actually exited:
        thread = process.GetThreadByID(tid)
        self.assertFalse(thread.IsValid(), "The thread exited")

        # Make sure the expression failed:
        self.assertFalse(result.GetError().Success(), "Expression failed.")

        self.assertState(process.GetState(), lldb.eStateStopped)
        self.assertEqual(
            len(lldbutil.get_threads_stopped_at_breakpoint(process, joined_bkpt)),
            1,
            "The surviving thread reached the join handoff",
        )
        self.assertTrue(target.BreakpointDelete(joined_bkpt.GetID()))

        # Make sure we can keep going:
        threads = lldbutil.continue_to_breakpoint(process, return_bkpt)
        if not threads:
            self.fail("didn't get any threads back after continuing")

        self.assertEqual(len(threads), 1, "One thread hit our breakpoint")
        thread = threads[0]
        frame = thread.frames[0]
        # Now get the return value, if we successfully caused the thread to exit
        # it should be 10, not 20.
        ret_val = frame.FindVariable("ret_val")
        self.assertSuccess(ret_val.GetError(), "Found ret_val")
        ret_val_value = ret_val.GetValueAsSigned(error)
        self.assertSuccess(error, "Got ret_val's value")
        self.assertEqual(ret_val_value, 10, "We put the right value in ret_val")
