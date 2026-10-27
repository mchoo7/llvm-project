import threading
import time

import lldb
from lldbsuite.test.lldbtest import *
from lldbsuite.test.decorators import *
from lldbsuite.test.gdbclientutils import *
from lldbsuite.test.lldbgdbclient import GDBRemoteTestBase


class TestAttachWaitConnected(GDBRemoteTestBase):
    TIMEOUT = 30

    @skipIfRemote
    @skipIfWindows
    def test_interrupt_wait_for_attach(self):
        """
        An interrupt ends a wait-for attach on a process that was connected
        before the attach started.
        """
        waiting = threading.Event()

        class WaitingResponder(MockGDBServerResponder):
            def other(self, packet):
                if packet.startswith(("vAttachWait", "vAttachOrWait")):
                    waiting.set()
                    return self.RESPONSE_NONE
                return super().other(packet)

            def qC(self):
                # No process on the server yet, so the connection stays
                # "connected" instead of becoming an attached, stopped process.
                return ""

            def qfThreadInfo(self):
                # An empty reply would make the client assume a bare-metal
                # stub with pid 1.
                return "E01"

            def interrupt(self):
                return "E04"

        self.server.responder = WaitingResponder()
        target = self.dbg.CreateTarget("")
        process = self.connect(target)

        listener = self.dbg.GetListener()
        event = lldb.SBEvent()
        deadline = time.monotonic() + self.TIMEOUT
        while process.GetState() != lldb.eStateConnected:
            self.assertLess(
                time.monotonic(),
                deadline,
                "never became connected, state: %s pid: %s packets: %s"
                % (
                    lldb.SBDebugger.StateAsCString(process.GetState()),
                    process.GetProcessID(),
                    self.server.responder.packetLog.get_received(),
                ),
            )
            listener.WaitForEvent(1, event)

        attach_info = lldb.SBAttachInfo()
        attach_info.SetExecutable("no-such-process")
        attach_info.SetWaitForLaunch(True, True)

        attach_error = lldb.SBError()
        target.Attach(attach_info, attach_error)
        self.assertSuccess(attach_error)

        self.assertTrue(
            waiting.wait(self.TIMEOUT),
            "server never received the wait-for attach: %s" % attach_error.GetCString(),
        )
        # Returning from the asynchronous Attach guarantees that its state is
        # published. Receiving the packet alone does not provide that guarantee.
        self.assertState(process.GetState(), lldb.eStateAttaching)
        process.SendAsyncInterrupt()
        deadline = time.monotonic() + self.TIMEOUT
        while process.GetState() != lldb.eStateExited:
            self.assertLess(
                time.monotonic(), deadline, "interrupt did not end the attach"
            )
            listener.WaitForEvent(1, event)
