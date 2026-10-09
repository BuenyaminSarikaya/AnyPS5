"""Check that the Linux extra block keeps its page offset and never shares a page with the highest guest segment."""

from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import tempfile

PT_LOAD = 1
PT_SCE_VERSION = 0x6FFFFF01
PAGE = 0x1000
DATA_OFFSET = 0x5000
DATA_VADDR = 0x8000
DATA_FILE_SIZE = 0x200
ENTRY = 0x10


def entry_check(data_memory_size):
    last = DATA_VADDR + data_memory_size - 1
    code = bytearray()
    for target, value, skip in ((DATA_VADDR, 0xA5, 0x0A), (last, 0xA5 if data_memory_size == DATA_FILE_SIZE else 0, 0x01)):
        code += b"\x80\x3d" + struct.pack("<i", target - (ENTRY + len(code) + 7)) + bytes([value, 0x75, skip])
    return bytes(code) + b"\xcc\x0f\x0b"


def fixture(data_memory_size, file_size):
    image = bytearray(file_size)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16,
                     3, 62, 1, ENTRY, 64, 0, 0, 64, 56, 7, 64, 0, 0)
    check = entry_check(data_memory_size)
    image[0x4000 + ENTRY:0x4000 + ENTRY + len(check)] = check
    tags = [(5, 0x600), (10, 1), (6, 0x620), (11, 24), (7, 0x700), (8, 0), (9, 24), (0, 0)]
    struct.pack_into("<IIQQQQQQ", image, 64,
                     PT_LOAD, 5, 0x4000, 0, 0, 0x1000, 0x1000, 0x4000)
    struct.pack_into("<IIQQQQQQ", image, 120,
                     2, 6, 0x600 + 0x4000, 0x600, 0x600, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into("<IIQQQQQQ", image, 176,
                     PT_LOAD, 6, DATA_OFFSET, DATA_VADDR, DATA_VADDR, DATA_FILE_SIZE, data_memory_size, 0x1000)
    for index in range(3, 7):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56, PT_SCE_VERSION, 0, 0, 0, 0, 0, 0, 1)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x4600 + index * 16, *tag)
    image[DATA_OFFSET:DATA_OFFSET + DATA_FILE_SIZE] = b"\xa5" * DATA_FILE_SIZE
    image[0x6000:] = b"\x5a" * (file_size - 0x6000)
    return image


def page_up(value):
    return (value + PAGE - 1) & ~(PAGE - 1)


def load(elf):
    phoff, = struct.unpack_from("<Q", elf, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", elf, 0x36)
    headers = [struct.unpack_from("<IIQQQQQQ", elf, phoff + index * phentsize) for index in range(phnum)]
    segments = [header for header in headers if header[0] == PT_LOAD]
    memory = bytearray(max(page_up(segment[3] + segment[6]) for segment in segments))
    for _, _, offset, vaddr, _, file_size, memory_size, _ in segments:
        start = vaddr & ~(PAGE - 1)
        file_end = vaddr + file_size
        if file_size:
            end = page_up(file_end)
            source = offset - (vaddr - start)
            chunk = elf[source:source + end - start]
            memory[start:end] = chunk + bytes(end - start - len(chunk))
        if memory_size > file_size:
            end = page_up(vaddr + memory_size)
            memory[file_end:end] = bytes(end - file_end)
    return segments, memory


def main():
    relinker = Path(sys.argv[1]).resolve()
    failures = []
    with tempfile.TemporaryDirectory(prefix="anyps5-extra-block-page-") as directory:
        work = Path(directory)
        for data_memory_size in (0x200, 0x300, 0x1000):
            for file_size in (0x8000, 0x8100, 0x8200, 0x8300, 0x8F00):
                name = f"{data_memory_size:x}-{file_size:x}"
                source = work / (name + ".elf")
                output = work / (name + ".out")
                source.write_bytes(fixture(data_memory_size, file_size))
                result = subprocess.run([str(relinker), "--skip-sce-module", str(source), str(output)],
                                        capture_output=True, text=True, timeout=20)
                if result.returncode != 0:
                    failures.append((name, result.returncode, result.stdout, result.stderr))
                    continue
                elf = output.read_bytes()
                segments, memory = load(elf)
                for _, _, offset, vaddr, _, segment_file_size, segment_memory_size, _ in segments:
                    if (offset - vaddr) % PAGE:
                        failures.append((name, "p_offset and p_vaddr differ modulo the page size", hex(offset), hex(vaddr)))
                    expected = elf[offset:offset + segment_file_size] + bytes(segment_memory_size - segment_file_size)
                    if memory[vaddr:vaddr + segment_memory_size] != expected:
                        failures.append((name, "PT_LOAD overwritten by a later PT_LOAD", hex(vaddr), hex(segment_memory_size),
                                         [tuple(hex(field) for field in segment[2:7]) for segment in segments]))
                if sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
                    output.chmod(0o755)
                    executed = subprocess.run([str(output)], capture_output=True, timeout=20)
                    if executed.returncode != -signal.SIGTRAP:
                        failures.append((name, "entry check did not end in int3", executed.returncode))
    if failures:
        raise AssertionError(failures)
    print("Linux extra block page tests passed")


if __name__ == "__main__":
    main()
