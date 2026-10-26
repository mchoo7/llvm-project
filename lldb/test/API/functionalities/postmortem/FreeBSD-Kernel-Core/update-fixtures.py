#!/usr/bin/env python3
"""Add metadata used by LLDB to the reduced FreeBSD 13 kernel-core fixtures.

The original fixtures retain only selected kernel memory and symbols. Reserve
16 unused bytes near hz for a stopped-CPU mask, mp_maxid and
osreldate, and export their synthetic addresses in the kernel YAML files.
Run this script from any directory to reproduce these fixture updates.

The minidump translation follows FreeBSD libkvm's kvm_minidump_{amd64,
aarch64,i386}.c and kvm_private.c. All fixtures use 4 KiB pages.
"""

import bz2
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parent
PAGE = 4096
FRAME = 0x000FFFFFFFFFF000
METADATA_ADDRESSES = {
    "amd64": 0xFFFFFFFF81CD4C30,
    "arm64": 0xFFFF000000E26540,
    "i386": 0x1D405E0,
}


def round_page(size):
    return (size + PAGE - 1) & -PAGE


class Minidump:
    def __init__(self, data, arch):
        self.data = data
        self.arch = arch
        version, msgsize, mapsize, pmapsize = struct.unpack_from("<4I", data, 24)
        if arch == "i386":
            self.kernbase, self.pae, availsize = struct.unpack_from("<3I", data, 40)
        elif arch == "amd64":
            self.kernbase = struct.unpack_from("<Q", data, 40)[0]
            availsize = struct.unpack_from("<I", data, 64)[0]
        else:
            self.kernbase = struct.unpack_from("<Q", data, 40)[0]
            availsize = struct.unpack_from("<I", data, 72)[0]
        availoff = PAGE + round_page(msgsize)
        mapoff = availoff + round_page(availsize)
        self.pmapoff = mapoff + round_page(mapsize)
        self.sparseoff = self.pmapoff + round_page(pmapsize)
        self.bitmap = int.from_bytes(data[mapoff : mapoff + mapsize], "little")
        self.ranges = []
        for off in range(availoff, availoff + availsize, 16):
            start, end = struct.unpack_from("<QQ", data, off)
            if end == 0:
                break
            self.ranges.append((start, end))

    def physical_offset(self, address):
        preceding = 0
        for start, end in self.ranges:
            if start <= address < end:
                bit = preceding + (address // PAGE - start // PAGE)
                if not (self.bitmap >> bit) & 1:
                    raise ValueError("physical page absent from fixture")
                count = (self.bitmap & ((1 << bit) - 1)).bit_count()
                return self.sparseoff + count * PAGE + address % PAGE
            preceding += (end + PAGE - 1) // PAGE - start // PAGE
        raise ValueError("physical address outside dump_avail")

    def virtual_offset(self, address):
        if self.arch == "amd64":
            index = (address - self.kernbase) >> 21
            pde = struct.unpack_from("<Q", self.data, self.pmapoff + index * 8)[0]
            if not pde & 1:
                raise ValueError("invalid page directory entry")
            if pde & 0x80:
                physical = (pde & (FRAME & ~0x1FFFFF)) + (address & 0x1FFFFF)
            else:
                offset = self.physical_offset(pde & FRAME)
                index = (address >> 12) & 511
                pte = struct.unpack_from("<Q", self.data, offset + index * 8)[0]
                if not pte & 1:
                    raise ValueError("invalid page table entry")
                physical = (pte & FRAME) + address % PAGE
        else:
            index = (address - self.kernbase) >> 12
            size = 4 if self.arch == "i386" and not self.pae else 8
            fmt = "<I" if size == 4 else "<Q"
            pte = struct.unpack_from(fmt, self.data, self.pmapoff + index * size)[0]
            if not pte & 1:
                raise ValueError("invalid page table entry")
            physical = (pte & FRAME) + address % PAGE
        return self.physical_offset(physical)


def update_minidump(path, arch, address, metadata):
    data = bytearray(bz2.decompress(path.read_bytes()))
    offset = Minidump(data, arch).virtual_offset(address)
    # Refuse to overwrite memory retained for another fixture assertion.
    if data[offset : offset + 16] not in (bytes(16), metadata):
        raise ValueError(f"{path.name}: metadata would overwrite retained data")
    data[offset : offset + 16] = metadata
    path.write_bytes(bz2.compress(data))


def update_full_dump(path, address, metadata):
    data = bytearray(bz2.decompress(path.read_bytes()))
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    physical = address - 0xFFFFFFFF80000000
    for index in range(phnum):
        ph = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        if ph[0] == 1 and ph[4] <= physical < ph[4] + ph[5]:
            offset = ph[2] + physical - ph[4]
            if data[offset : offset + 16] not in (bytes(16), metadata):
                raise ValueError("full dump metadata would overwrite retained data")
            data[offset : offset + 16] = metadata

    path.write_bytes(bz2.compress(data))


def main():
    for arch in ("amd64", "arm64", "i386"):
        yaml = ROOT / f"kernel-{arch}.yaml"
        text = yaml.read_text()
        address = METADATA_ADDRESSES[arch]
        # The retained on-CPU contexts are stopped, and all these kernels use
        # the FreeBSD 13 PCB layout and array form of stoppcbs.
        metadata = struct.pack("<QII", 0xFFFFFFFFFFFFFFFF, 63, 1300000)
        update_minidump(ROOT / f"vmcore-{arch}-minidump.bz2", arch, address, metadata)
        if arch == "amd64":
            update_full_dump(ROOT / "vmcore-amd64-full.bz2", address, metadata)
        if "Name:            stopped_cpus" not in text:
            text += "# Synthetic metadata in unused bytes near hz; see update-fixtures.py.\n"
            for name, offset, size in (("stopped_cpus", 0, 8),
                                       ("mp_maxid", 8, 4), ("osreldate", 12, 4)):
                text += (
                    f"  - Name:            {name}\n"
                    "    Type:            STT_OBJECT\n"
                    "    Section:         .bss\n"
                    "    Binding:         STB_GLOBAL\n"
                    f"    Value:           0x{address + offset:X}\n"
                    f"    Size:            0x{size:X}\n"
                )
            yaml.write_text(text)


if __name__ == "__main__":
    main()
