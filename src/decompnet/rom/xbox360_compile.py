"""Local Xbox 360 compiler experiments, separate from coordinator match scoring.

Accepts an explicitly selected XDK cl.exe or OXDK's patched clang. No SDK is
downloaded. Relocatable objects with unresolved references cannot be exact matches.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import hashlib
from pathlib import Path
import struct
import subprocess
import sys

from .xbox360 import Xbox360Error, MAX_EXECUTABLE


def object_function(data: bytes, name: str) -> tuple[bytes, int]:
    """Return explicit-size function bytes and unresolved relocation count."""
    def block(at, size):
        if at < 0 or size < 0 or at + size > len(data):
            raise Xbox360Error('object structure out of bounds')
        return data[at:at + size]
    if data[:4] == b'\x7fELF':
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(io.BytesIO(data))
        if elf['e_machine'] != 'EM_PPC' or elf.little_endian or elf.elfclass != 32 or elf['e_type'] != 'ET_REL':
            raise Xbox360Error('expected a big-endian PowerPC32 ELF relocatable object')
        symbols = elf.get_section_by_name('.symtab')
        matches = symbols.get_symbol_by_name(name) if symbols else None
        if not matches or len(matches) != 1:
            raise Xbox360Error('function symbol missing or ambiguous')
        s = matches[0]
        if s['st_info']['type'] != 'STT_FUNC' or not isinstance(s['st_shndx'], int) or not s['st_size']:
            raise Xbox360Error('function has no explicit size or code section')
        section = elf.get_section(s['st_shndx'])
        start, size = s['st_value'], s['st_size']
        raw = section.data()
        if start + size > len(raw) or not section['sh_flags'] & 4:
            raise Xbox360Error('function extent outside executable section')
        relocs = sum(1 for sec in elf.iter_sections() if sec['sh_type'] in ('SHT_REL', 'SHT_RELA')
                     and sec['sh_info'] == s['st_shndx'] for r in sec.iter_relocations()
                     if start <= r['r_offset'] < start + size)
        return raw[start:start + size], relocs
    machine, count, _, symptr, syms, optional, _ = struct.unpack('<HHIIIHH', block(0, 20))
    if machine != 0x1f2 or optional:
        raise Xbox360Error('expected an Xbox 360 PowerPCBE COFF object')
    block(20, count * 40)
    block(symptr, syms * 18)
    strings = symptr + syms * 18
    string_size = struct.unpack('<I', block(strings, 4))[0]
    table = block(strings, string_size)
    def function_size(symbol_index):
        # XDK 3529 emits no function auxiliary symbol even with /Z7. Its
        # .pdata or CodeView procedure records carry the actual function size.
        sizes = set()
        for section in range(count):
            sh = 20 + section * 40
            section_name = block(sh, 8).rstrip(b'\0')
            rawsize, rawptr, relocptr = struct.unpack('<III', block(sh + 16, 12))
            nreloc = struct.unpack('<H', block(sh + 32, 2))[0]
            raw = block(rawptr, rawsize)
            relocs = [struct.unpack('<IIH', block(relocptr + j * 10, 10)) for j in range(nreloc)]
            if section_name == b'.pdata':
                for offset, index, kind in relocs:
                    if index == symbol_index and kind == 2 and offset % 8 == 0 and offset + 8 <= len(raw):
                        packed = struct.unpack_from('>I', raw, offset + 4)[0]
                        if packed & 0x40000000:
                            sizes.add(((packed >> 8) & 0x3fffff) * 4)
            if section_name != b'.debug$S' or raw[:4] != b'\x04\0\0\0':
                continue
            pos = 4
            while pos + 8 <= len(raw):
                kind, length = struct.unpack_from('<II', raw, pos)
                end = pos + 8 + length
                if end > len(raw):
                    raise Xbox360Error('truncated CodeView subsection')
                cursor = pos + 8
                if kind == 0xf1:
                    while cursor + 4 <= end:
                        record_length, record_kind = struct.unpack_from('<HH', raw, cursor)
                        if record_length < 2 or cursor + 2 + record_length > end:
                            raise Xbox360Error('invalid CodeView symbol record')
                        if record_kind in (0x110f, 0x1110) and record_length >= 37:
                            if any(at == cursor + 32 and index == symbol_index and reloc_kind == 11
                                   for at, index, reloc_kind in relocs):
                                sizes.add(struct.unpack_from('<I', raw, cursor + 16)[0])
                        cursor += record_length + 2
                pos = (end + 3) & ~3
        if len(sizes) != 1 or 0 in sizes:
            raise Xbox360Error('COFF function size missing or inconsistent; compile with /Z7')
        return sizes.pop()
    i = 0
    while i < syms:
        p = symptr + i * 18
        rawname, value, section_id, typ, storage, aux = struct.unpack('<8sIhHBB', block(p, 18))
        if i + 1 + aux > syms:
            raise Xbox360Error('truncated auxiliary symbols')
        if rawname[:4] == bytes(4):
            offset = struct.unpack_from('<I', rawname, 4)[0]
            if not 4 <= offset < len(table) or b'\0' not in table[offset:]:
                raise Xbox360Error('invalid COFF symbol name')
            symbol = table[offset:].split(b'\0', 1)[0].decode('utf-8', 'replace')
        else:
            symbol = rawname.split(b'\0', 1)[0].decode('utf-8', 'replace')
        if symbol == name and typ & 0x20 and 1 <= section_id <= count:
            # COFF function-definition auxiliary record provides TotalSize.
            size = struct.unpack('<I', block(p + 18 + 4, 4))[0] if aux and storage == 2 else function_size(i)
            sh = 20 + (section_id - 1) * 40
            rawsize, rawptr, relocptr = struct.unpack('<III', block(sh + 16, 12))
            nreloc = struct.unpack('<H', block(sh + 32, 2))[0]
            flags = struct.unpack('<I', block(sh + 36, 4))[0]
            if not size or value + size > rawsize or not flags & 0x20000000 or flags & 0x01000000:
                raise Xbox360Error('unsupported COFF function extent or relocation overflow')
            relocs = sum(1 for j in range(nreloc)
                         if value <= struct.unpack('<I', block(relocptr + j * 10, 10)[:4])[0] < value + size)
            return block(rawptr + value, size), relocs
        i += 1 + aux
    raise Xbox360Error('function symbol not found')


def run(project: Path, source: Path, output: Path, compiler: Path, backend: str,
        symbol: str, address: int, flags: list[str], *, xdk: Path | None = None,
        size: int | None = None) -> dict:
    from ..compiler import check_source
    source = source.resolve()
    check_source(source.read_text(encoding='utf-8'))
    if not compiler.is_file():
        raise Xbox360Error(f'compiler not found: {compiler}')
    info = json.loads((project / 'inspection.json').read_text(encoding='utf-8'))
    manifest = json.loads((project / 'functions.json').read_text(encoding='utf-8'))
    target = next((f.copy() for f in manifest['functions'] if f['address'] == address), None)
    if target is None:
        raise Xbox360Error('comparison requires a function candidate in functions.json')
    if size is not None:
        if size <= 0 or size % 4 or (target['size'] is not None and target['size'] != size):
            raise Xbox360Error('explicit size must be instruction aligned and agree with known bounds')
        target['size'] = size
    if target['size'] is None:
        raise Xbox360Error('unbounded candidate: supply --size after reviewing its disassembly')
    if not any(s['executable'] and info['pe']['image_base'] + s['rva'] <= address
               and address + target['size'] <= info['pe']['image_base'] + s['rva'] + s['size']
               for s in info['pe']['sections']):
        raise Xbox360Error('function extent outside executable sections')
    image = (project / 'image.bin').read_bytes()
    offset = address - info['pe']['image_base']
    if offset < 0 or offset + target['size'] > len(image):
        raise Xbox360Error('target function outside image')
    output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    (output / '.gitignore').write_text('*\n', encoding='utf-8')
    obj = output / ('function.obj' if backend == 'xdk' else 'function.o')
    environment = os.environ.copy()
    if backend == 'xdk':
        xdk = xdk or compiler.resolve().parents[2]
        if not (xdk / 'include' / 'xbox').is_dir() or not (xdk / 'lib' / 'xbox').is_dir():
            raise Xbox360Error('XDK root must contain include/xbox and lib/xbox')
        environment['XEDK'] = str(xdk.resolve()) + os.sep
        environment['INCLUDE'] = str((xdk / 'include' / 'xbox').resolve())
        environment['LIB'] = str((xdk / 'lib' / 'xbox').resolve())
        environment['PATH'] = str(compiler.resolve().parent) + os.pathsep + environment.get('PATH', '')
    if backend == 'xdk':
        command = [str(compiler.resolve()), '/nologo', '/c', '/O2', '/Z7', *flags, str(source), '/Fo' + str(obj)]
    elif backend == 'oxdk':
        command = [str(compiler.resolve()), '-target', 'powerpc-unknown-none-elf', '-ffreestanding',
                   '-fno-builtin', '-fms-extensions', '-fshort-wchar', '-O2', *flags,
                   '-Xclang', '-target-feature', '-Xclang', '+xenon-abi', '-c', str(source), '-o', str(obj)]
    else:
        raise Xbox360Error('unknown compiler backend')
    with (output / 'compiler.log').open('w', encoding='utf-8') as log:
        try:
            result = subprocess.run(command, cwd=output, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        except subprocess.TimeoutExpired as exc:
            raise Xbox360Error('compiler timed out; see compiler.log') from exc
    log = (output / 'compiler.log').read_text(encoding='utf-8', errors='replace')
    if result.returncode or not obj.is_file() or (backend == 'oxdk' and 'not a recognized feature' in log):
        raise Xbox360Error('compiler failed or lacks Xenon ABI support; see compiler.log')
    if obj.stat().st_size > MAX_EXECUTABLE:
        raise Xbox360Error('compiler object exceeds size limit')
    code, relocations = object_function(obj.read_bytes(), symbol)
    original = image[offset:offset + target['size']]
    report = dict(backend=backend, symbol=symbol, address=f'0x{address:08X}', compiled=True,
                  original_size=len(original), compiled_size=len(code), unresolved_relocations=relocations,
                  exact_bytes=(code == original) if not relocations else None,
                  different_bytes=(sum(a != b for a, b in zip(code, original)) + abs(len(code) - len(original))) if not relocations else None,
                  bounds_source='explicit' if size is not None else target['source'],
                  compiler=str(compiler.resolve()), compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
                  source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), command=command,
                  limitation='Raw byte comparison only; no relocation linking, ABI or semantic verification. Not submitted to web match scoring.')
    (output / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, help='compiler executable; XDK can instead use --xdk or XEDK')
    parser.add_argument('--xdk', type=Path, help='extracted XDK root containing bin/win32, include/xbox, lib/xbox')
    parser.add_argument('--size', type=lambda s: int(s, 0), help='reviewed byte length for an unbounded candidate')
    parser.add_argument('--backend', choices=['xdk', 'oxdk'], required=True)
    parser.add_argument('--symbol', required=True)
    parser.add_argument('--address', type=lambda s: int(s, 0), required=True)
    parser.add_argument('--flag', action='append', default=[], help='additional local compiler option; use --flag=VALUE')
    args = parser.parse_args(argv)
    try:
        xdk = args.xdk or (Path(os.environ['XEDK']) if os.environ.get('XEDK') else None)
        compiler = args.compiler or (xdk / 'bin' / 'win32' / 'cl.exe' if xdk and args.backend == 'xdk' else None)
        if compiler is None:
            raise Xbox360Error('supply --compiler, or --xdk/XEDK with --backend xdk')
        print(json.dumps(run(args.project, args.source, args.output, compiler, args.backend,
                             args.symbol, args.address, args.flag, xdk=xdk, size=args.size), indent=2))
        return 0
    except (OSError, ValueError, ImportError, struct.error) as exc:
        print(f'Xbox 360 compilation failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
