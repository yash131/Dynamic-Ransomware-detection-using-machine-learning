"""
Generate two INERT PE-format test fixtures in ../test_files/.

Both are header-only stubs: section bodies are zero bytes plus a text marker, the entry point
is 0, and they carry NO executable code, so they cannot do anything even if launched. They
use a .bin extension so they are never double-click executable.

* benign_sample.bin               header profile of a modern MSVC-built tool (debug dir, ASLR/NX
                                  flags, linker 14, OS 6) - modelled on setuptools' launcher stubs.
* simulated_malicious_sample.bin  header profile of a legacy/packed-style binary (no debug dir,
                                  no DllCharacteristics, OS 4, linker 6, large resource blob).
                                  NOT real malware. It only exercises the "malicious" path.

The verdicts displayed in the dashboard come from the real trained models; nothing here
hard-codes a result.
"""
import struct, pathlib, hashlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "test_files"
FILE_ALIGN, SECT_ALIGN, HDR_SIZE = 0x200, 0x1000, 0x400


def build_pe(*, pe32plus, machine, linker=(14, 0), os_major=6, image_major=0, dll_chars=0,
             debug=(0, 0), resource=(0, 0), iat=(0, 0), stack_reserve=0x100000,
             sections=(".text", ".rdata", ".data", ".rsrc"), marker=b""):
    n = len(sections)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)                    # e_lfanew
    dos[0x40:0x40 + 40] = b"INERT TEST FIXTURE - NOT EXECUTABLE CODE"[:40]

    opt_magic = 0x20B if pe32plus else 0x10B
    opt_size = 240 if pe32plus else 224
    chars = 0x0022 if pe32plus else 0x0102                     # EXECUTABLE_IMAGE | LARGE_ADDR / 32BIT
    coff = struct.pack("<HHIIIHH", machine, n, 0x5F000000, 0, 0, opt_size, chars)

    size_of_image = SECT_ALIGN * (n + 1)
    opt = struct.pack("<HBB", opt_magic, *linker)
    opt += struct.pack("<III", FILE_ALIGN, FILE_ALIGN, FILE_ALIGN)  # SizeOfCode/Init/Uninit
    opt += struct.pack("<II", 0, SECT_ALIGN)                         # EntryPoint = 0 (inert), BaseOfCode
    if pe32plus:
        opt += struct.pack("<Q", 0x140000000)
    else:
        opt += struct.pack("<II", SECT_ALIGN * 3, 0x400000)          # BaseOfData, ImageBase
    opt += struct.pack("<II", SECT_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHH", os_major, 0, image_major, 0, 6, 0)  # OS, Image, Subsystem versions
    opt += struct.pack("<IIII", 0, size_of_image, HDR_SIZE, 0)        # Win32Ver, SizeOfImage, SizeOfHeaders, CheckSum
    opt += struct.pack("<HH", 3, dll_chars)                           # Subsystem=CUI, DllCharacteristics
    if pe32plus:
        opt += struct.pack("<QQQQ", stack_reserve, 0x1000, 0x100000, 0x1000)
    else:
        opt += struct.pack("<IIII", stack_reserve, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)                                  # LoaderFlags, NumberOfRvaAndSizes
    dirs = [(0, 0)] * 16
    dirs[2] = resource
    dirs[6] = debug
    dirs[12] = iat
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)
    assert len(opt) == opt_size, (len(opt), opt_size)

    table, body = b"", b""
    for i, name in enumerate(sections):
        raw_ptr = HDR_SIZE + i * FILE_ALIGN
        flags = 0x60000020 if name == ".text" else 0x40000040
        table += struct.pack("<8sIIIIIIHHI", name.encode(), FILE_ALIGN, SECT_ALIGN * (i + 1),
                             FILE_ALIGN, raw_ptr, 0, 0, 0, 0, flags)
        sec = bytearray(FILE_ALIGN)                                   # zero bytes: no code
        if name == ".rdata" and marker:
            sec[0x100:0x100 + len(marker)] = marker
        body += bytes(sec)

    headers = bytes(dos) + b"PE\0\0" + coff + opt + table
    headers = headers.ljust(HDR_SIZE, b"\0")
    return headers + body


def main():
    OUT.mkdir(exist_ok=True)
    benign = build_pe(
        pe32plus=False, machine=0x014C, linker=(14, 0), os_major=6, dll_chars=0x8140,
        debug=(0x32D0, 28), resource=(0x4000 + 0x1000, 480), iat=(0x3000, 0x100),
        marker=b"INERT TEST FIXTURE: benign-profile header-only stub. Contains no code.")
    malicious = build_pe(
        pe32plus=False, machine=0x014C, linker=(6, 0), os_major=4, dll_chars=0,
        debug=(0, 0), resource=(0x5000, 18000), iat=(0x3000, 0x100), sections=(".text", ".data", ".rsrc"),
        marker=b"INERT TEST FIXTURE: legacy-profile header-only stub. NOT real malware. No code.")
    for name, blob in [("benign_sample.bin", benign), ("simulated_malicious_sample.bin", malicious)]:
        (OUT / name).write_bytes(blob)
        print(f"wrote {name}: {len(blob)} bytes sha256={hashlib.sha256(blob).hexdigest()[:16]}...")


if __name__ == "__main__":
    main()
