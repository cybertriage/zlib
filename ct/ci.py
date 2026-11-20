#!/usr/bin/env python3
"""Steps of the Cyber Triage build of zlib that need more than a shell line.

Usage:
  ci.py fetch-mbedtls <directory>
      Downloads the Mbed TLS package that ct/mbedtls.json pins, checks its
      SHA-256, extracts it into <directory> and prints the package's path.
  ci.py check --lib <zlibstat.lib>
      Checks the static library. Exits 1 if any check fails.
  ci.py run-probe --exe <probe.exe> --dir <directory>
      Runs the probe, which writes gzip files into <directory>, and checks
      each hash and size it reports against the file, with Python's hashlib.
      Exits 1 if any check fails.

Runs on Windows. fetch-mbedtls needs gh and a GH_TOKEN that can read the
Mbed TLS repository. check finds dumpbin.exe with vswhere when it is not on
PATH.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))

# Functions Cyber Triage calls, as ZLIB_WINAPI (stdcall) decorates them.
EXPECTED_EXPORTS = (
    "_gz_hash_init@4", "_gzclose_hash@12", "_gzclose_hash_w@12", "_gzopen_w@8",
    "_gzwrite@12", "_gzoffset@4", "_gzclose@4", "_deflateInit_@16", "_deflate@8",
    "_deflateEnd@4", "_compress@16", "_adler32@12",
)

# Mbed TLS functions the hashing patch calls. The library leaves them to the
# Mbed TLS library the executable links.
MBEDTLS_IMPORTS = (
    "_mbedtls_sha256_init", "_mbedtls_sha256_starts", "_mbedtls_sha256_update",
    "_mbedtls_sha256_finish", "_mbedtls_sha256_free",
)


def find_tool(name):
    """Returns the path of an MSVC tool, from PATH or else the newest one vswhere finds."""
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    vswhere = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                           "Microsoft Visual Studio", "Installer", "vswhere.exe")
    output = subprocess.run(
        [vswhere, "-latest", "-products", "*", "-find", rf"VC\Tools\MSVC\**\bin\Hostx64\x86\{name}"],
        check=True, stdout=subprocess.PIPE, universal_newlines=True).stdout.splitlines()
    output = [line.strip() for line in output if line.strip()]
    if not output:
        raise RuntimeError(f"vswhere found no {name}")
    return sorted(output)[-1]


def run(arguments, check=True):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            universal_newlines=True, errors="replace")
    if check and result.returncode != 0:
        raise RuntimeError(f"{arguments[0]} exited with {result.returncode}:\n{result.stdout}")
    return result


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file_object:
        for block in iter(lambda: file_object.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---- COFF archive parsing -------------------------------------------------

def archive_members(data):
    """Yields (name, body) for each object in a COFF archive (.lib)."""
    if data[:8] != b"!<arch>\n":
        raise ValueError("not a COFF archive")
    offset = 8
    long_names = b""
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        name = header[:16].decode("latin1").rstrip()
        size = int(header[48:58].decode().strip())
        body = data[offset + 60:offset + 60 + size]
        if name == "//":
            long_names = body
        elif name not in ("/", "/<ECSYMBOLS>/"):
            if name.startswith("/") and name[1:].isdigit():
                start = int(name[1:])
                name = long_names[start:long_names.find(b"\0", start)].decode("latin1")
            yield name, body
        offset += 60 + size + (size & 1)


def codeview_symbols(section):
    """Yields (record type, payload) from a .debug$S section."""
    if len(section) < 4 or struct.unpack_from("<I", section, 0)[0] != 4:
        return
    offset = 4
    while offset + 8 <= len(section):
        kind, length = struct.unpack_from("<II", section, offset)
        if kind == 0xF1:  # DEBUG_S_SYMBOLS
            sub = section[offset + 8:offset + 8 + length]
            position = 0
            while position + 4 <= len(sub):
                record_length, record_type = struct.unpack_from("<HH", sub, position)
                yield record_type, sub[position + 4:position + 2 + record_length]
                position += 2 + record_length
        offset = (offset + 8 + length + 3) & ~3


def describe_object(body):
    """Returns what the checks need to know about one object file."""
    if struct.unpack_from("<HH", body, 0) == (0, 0xFFFF):
        return {"anonymous": True}
    machine, sections, _, symbol_table, symbols, optional_header, _ = struct.unpack_from("<HHIIIHH", body, 0)
    info = {"anonymous": False, "machine": machine, "directives": "", "compiler": None,
            "type_server": None, "defined": set(), "undefined": set()}
    for index in range(sections):
        header = body[20 + optional_header + index * 40:20 + optional_header + (index + 1) * 40]
        name = header[:8].rstrip(b"\0").decode("latin1")
        size, pointer = struct.unpack_from("<II", header, 16)
        raw = body[pointer:pointer + size]
        if name == ".drectve":
            info["directives"] += " " + raw.decode("latin1").strip("\0 ")
        elif name == ".debug$S":
            for record_type, payload in codeview_symbols(raw):
                if record_type == 0x113C:  # S_COMPILE3: front-end major, minor, build, QFE
                    info["compiler"] = "%d.%d.%d" % struct.unpack_from("<3H", payload, 6)
        elif name == ".debug$T" and len(raw) >= 8:
            # LF_TYPESERVER2 means the types are in a PDB the linker must find (/Zi).
            if struct.unpack_from("<I", raw, 0)[0] == 4 and struct.unpack_from("<H", raw, 6)[0] == 0x1515:
                info["type_server"] = raw[28:].split(b"\0")[0].decode("latin1")
    strings = symbol_table + symbols * 18
    index = 0
    while index < symbols:
        entry = body[symbol_table + index * 18:symbol_table + (index + 1) * 18]
        if entry[:4] == b"\0\0\0\0":
            start = strings + struct.unpack_from("<I", entry, 4)[0]
            name = body[start:body.find(b"\0", start)].decode("latin1")
        else:
            name = entry[:8].rstrip(b"\0").decode("latin1")
        section_number = struct.unpack_from("<h", entry, 12)[0]
        storage_class = entry[16]
        if storage_class == 2:  # IMAGE_SYM_CLASS_EXTERNAL
            if section_number == 0 and struct.unpack_from("<I", entry, 8)[0] == 0:
                info["undefined"].add(name)
            elif section_number > 0:
                info["defined"].add(name)
        index += 1 + entry[17]
    return info


# ---- commands ---------------------------------------------------------------

def fetch_mbedtls(arguments):
    with open(os.path.join(HERE, "mbedtls.json"), encoding="utf-8") as file_object:
        pin = json.load(file_object)
    os.makedirs(arguments.directory, exist_ok=True)
    download = tempfile.mkdtemp(dir=arguments.directory)
    if pin.get("tag"):
        print(f"Mbed TLS: release {pin['tag']} of {pin['repo']}, asset {pin['asset']}")
        run(["gh", "release", "download", pin["tag"], "--repo", pin["repo"],
             "--pattern", pin["asset"], "--dir", download])
    else:
        # Until Mbed TLS has a release: the package artifact of a ct_release run.
        artifact = pin["asset"][:-len(".zip")]
        print(f"Mbed TLS: artifact {artifact} of run {pin['run_id']} of {pin['repo']}")
        run(["gh", "run", "download", str(pin["run_id"]), "--repo", pin["repo"],
             "--name", artifact, "--dir", download])
    package = os.path.join(download, pin["asset"])
    digest = sha256_file(package)
    if digest != pin["sha256"]:
        print(f"SHA-256 of {pin['asset']} is {digest}, not the pinned {pin['sha256']}")
        return 1
    print(f"SHA-256 {digest} matches the pin")
    with zipfile.ZipFile(package) as archive:
        archive.extractall(arguments.directory)
    root = os.path.join(arguments.directory, pin["asset"][:-len(".zip")])
    print(open(os.path.join(root, "SOURCE.txt"), encoding="utf-8").read())
    return 0


def check(arguments):
    failures = []
    report = []

    def expect(ok, what):
        report.append(f"{'PASS' if ok else 'FAIL'}: {what}")
        if not ok:
            failures.append(what)

    with open(arguments.lib, "rb") as file_object:
        data = file_object.read()
    objects = [(name, describe_object(body)) for name, body in archive_members(data)]
    anonymous = [name for name, info in objects if info["anonymous"]]
    expect(not anonymous, f"no /GL (anonymous) objects; found {len(anonymous)}")
    described = [info for _, info in objects if not info["anonymous"]]
    report.append(f"objects: {' '.join(sorted(os.path.basename(name) for name, _ in objects))}")
    machines = Counter(hex(info["machine"]) for info in described)
    expect(set(machines) == {"0x14c"}, f"every object is x86; machines {dict(machines)}")
    type_servers = sorted({info["type_server"] for info in described if info["type_server"]})
    expect(not type_servers, f"debug info is in the objects (/Z7), not a PDB; PDB references {type_servers}")
    compilers = Counter(info["compiler"] for info in described)
    report.append(f"compilers (S_COMPILE3 front end): {dict(compilers)}")
    expect(len(compilers) == 1 and all(version and re.match(r"^19\.1\d\.", version) for version in compilers),
           "every object is compiled by the v141_xp compiler (19.1x)")

    dumpbin = find_tool("dumpbin.exe")
    directives = run([dumpbin, "/NOLOGO", "/DIRECTIVES", arguments.lib]).stdout
    default_libs = sorted({match.lower() for match in re.findall(r"/DEFAULTLIB:\"?([^\s\"]+)", directives, re.I)})
    expect(not default_libs, f"no object names a default library (/Zl), so the executable's C runtime is used; found {default_libs}")

    defined = set().union(*(info["defined"] for info in described))
    undefined = set().union(*(info["undefined"] for info in described)) - defined
    missing = [name for name in EXPECTED_EXPORTS if name not in defined]
    expect(not missing, f"defines the stdcall (ZLIB_WINAPI) functions Cyber Triage calls; missing {missing}")
    folded = sorted(name for name in defined if name.startswith("_mbedtls_"))
    expect(not folded, f"has no Mbed TLS code folded in; defines {folded[:5]}")
    unresolved = [name for name in MBEDTLS_IMPORTS if name not in undefined]
    expect(not unresolved, f"leaves the Mbed TLS SHA-256 functions to the executable; does not reference {unresolved}")
    windows = sorted(name for name in undefined if name.startswith("__imp_"))
    report.append(f"Windows APIs imported: {' '.join(windows) if windows else 'none'}")
    report.append(f"external references: {' '.join(sorted(undefined))}")

    print("\n".join(report))
    print(f"{len(failures)} check(s) failed" if failures else "all checks passed")
    return 1 if failures else 0


def run_probe(arguments):
    os.makedirs(arguments.dir, exist_ok=True)
    result = run([os.path.abspath(arguments.exe), os.path.abspath(arguments.dir)], check=False)
    print(result.stdout.rstrip())
    failures = 0 if result.returncode == 0 else 1
    if failures:
        print(f"FAIL: the probe exited {result.returncode}")
    files = 0
    for match in re.finditer(r"^([0-9a-f]{64}) (-?\d+) (.+)$", result.stdout, re.M):
        expected_hash, size, path = match.group(1), int(match.group(2)), match.group(3).strip()
        files += 1
        actual_hash, actual_size = sha256_file(path), os.path.getsize(path)
        ok = actual_hash == expected_hash and actual_size == size
        print(f"{'PASS' if ok else 'FAIL'}: hashlib agrees for {os.path.basename(path)}: {actual_hash} {actual_size}")
        failures += not ok
    if files < 4:
        print(f"FAIL: the probe reported {files} files, not at least 4")
        failures += 1
    print(f"{failures} check(s) failed" if failures else "all checks passed")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command")
    fetch_parser = commands.add_parser("fetch-mbedtls")
    fetch_parser.add_argument("directory")
    check_parser = commands.add_parser("check")
    check_parser.add_argument("--lib", required=True)
    probe_parser = commands.add_parser("run-probe")
    probe_parser.add_argument("--exe", required=True)
    probe_parser.add_argument("--dir", required=True)
    arguments = parser.parse_args()
    if arguments.command == "fetch-mbedtls":
        return fetch_mbedtls(arguments)
    if arguments.command == "check":
        return check(arguments)
    if arguments.command == "run-probe":
        return run_probe(arguments)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
