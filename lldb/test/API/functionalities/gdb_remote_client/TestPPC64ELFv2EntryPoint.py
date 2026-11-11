import lldb
from lldbsuite.test import lldbutil
from lldbsuite.test.decorators import skipIfLLVMTargetMissing, skipIfXmlSupportMissing
from lldbsuite.test.gdbclientutils import (
    MockGDBServerResponder,
    hex_decode_bytes,
    hex_encode_bytes,
)
from lldbsuite.test.lldbgdbclient import GDBRemoteTestBase


class PPC64Responder(MockGDBServerResponder):
    def qSupported(self, client_supported):
        return super().qSupported(client_supported) + ";qXfer:auxv:read+"

    def qProcessInfo(self):
        return "pid:400000;ptrsize:8;endian:big;triple:%s;" % hex_encode_bytes(
            "powerpc64-unknown-freebsd"
        )

    def qHostInfo(self):
        return "ptrsize:8;endian:big;"

    def qfThreadInfo(self):
        return "m400000"

    def qXferRead(self, obj, annex, offset, length):
        if obj == "features" and annex == "target.xml":
            return (
                """<?xml version="1.0"?>
                <target version="1.0">
                  <architecture>powerpc:common64</architecture>
                  <feature name="org.gnu.gdb.power.core">
                    <reg name="pc" bitsize="64" regnum="0" generic="pc"/>
                  </feature>
                </target>""",
                False,
            )
        if obj == "auxv":
            # AT_ENTRY points directly to code in ELFv2. The executable has a
            # file entry point of 0x1000 and is loaded with a 0x10000000 bias.
            return (
                hex_decode_bytes(
                    "00000000000000090000000010001000"
                    "00000000000000000000000000000000"
                ),
                False,
            )
        return None, False

    def readRegisters(self):
        return "0000000010001000"

    def readRegister(self, register):
        return self.readRegisters()

    def readMemory(self, addr, length):
        # These instructions must never be interpreted as a function descriptor.
        data = bytes.fromhex("3c4c000238429d88") + bytes(0x1000)
        offset = addr - 0x10001000
        if 0 <= offset and offset + length <= len(data):
            return data[offset : offset + length].hex()
        return "E01"

    def setBreakpoint(self, packet):
        return "OK"


class TestPPC64ELFv2EntryPoint(GDBRemoteTestBase):
    @skipIfXmlSupportMissing
    @skipIfLLVMTargetMissing("PowerPC")
    def test_big_endian_elfv2_load_address(self):
        executable = self.getBuildArtifact("ppc64-elfv2")
        self.yaml2obj("ppc64-elfv2.yaml", executable)
        # yaml2obj does not name the PPC64 ABI flag values. Set EF_PPC64_ABI
        # to ELFv2 before LLDB opens the object file.
        with open(executable, "r+b") as binary:
            binary.seek(48)
            binary.write((2).to_bytes(4, "big"))

        self.server.responder = PPC64Responder()
        target = self.dbg.CreateTarget(executable)
        process = self.connect(target)
        lldbutil.expect_state_changes(
            self, self.dbg.GetListener(), process, [lldb.eStateStopped]
        )

        text = target.GetModuleAtIndex(0).FindSection(".text")
        self.assertTrue(text.IsValid())
        self.assertEqual(text.GetLoadAddress(target), 0x10001000)
