"""Experimental Xbox 360 disc/XEX inspection with optional analysis backends.

Format references (independent implementation): Xenia's disc_image_device.cc and
kernel/util/xex2_info.h. XDVDFS offsets are partition-relative; XEX words are BE.
Inspection uses the standard library. Loading requires the xbox360 extra.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

MAGIC = b"MICROSOFT*XBOX*MEDIA"
SECTOR = 2048
PARTITIONS = (0, 0xFB20, 0x20600, 0x2080000, 0xFD90000)
MAX_DIRECTORY = 32 << 20
MAX_EXECUTABLE = 256 << 20
LIMITATION = ("Xbox 360 uses a separate experimental CLI workflow. "
              "Use 'decomp xbox360 GAME.iso --output NEW_DIRECTORY --load' for AES/basic XEX loading "
              "and function discovery; add --ghidra INSTALL_DIRECTORY for draft C. "
              "The web matching workflow is not supported; draft C is not verified matching source.")


class Xbox360Error(ValueError):
    pass


class Disc:
    """A bounded, read-only view of an XDVDFS game partition."""
    def __init__(self, stream):
        self.stream = stream
        stream.seek(0, 2)
        self.size = stream.tell()
        self.partition = None
        for offset in PARTITIONS:
            at = offset + 32 * SECTOR
            if at + SECTOR <= self.size and self.read(at, len(MAGIC)) == MAGIC:
                if self.read(at + SECTOR - len(MAGIC), len(MAGIC)) != MAGIC:
                    raise Xbox360Error("damaged XDVDFS volume descriptor")
                self.partition = offset
                self.root_sector, self.root_size = struct.unpack("<II", self.read(at + 20, 8))
                break
        if self.partition is None:
            raise Xbox360Error("no XDVDFS game partition at a supported disc offset")

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise Xbox360Error("XDVDFS extent is outside the image")
        self.stream.seek(offset)
        data = self.stream.read(size)
        if len(data) != size:
            raise Xbox360Error("truncated XDVDFS image")
        return data

    def entries(self, sector: int, size: int) -> list[dict]:
        if not 14 <= size <= MAX_DIRECTORY:
            raise Xbox360Error("invalid XDVDFS directory size")
        data = self.read(self.partition + sector * SECTOR, size)
        pending, seen, names, result = [0], set(), set(), []
        while pending:
            at = pending.pop()
            if at in seen or at + 14 > len(data):
                raise Xbox360Error("cyclic or truncated XDVDFS directory")
            seen.add(at)
            left, right, start, length, attrs, count = struct.unpack_from("<HHIIBB", data, at)
            if not count or at + 14 + count > len(data):
                raise Xbox360Error("invalid XDVDFS filename length")
            name = data[at + 14:at + 14 + count].decode("ascii", "strict")
            if name in (".", "..") or any(c in name for c in '/\\:\x00') or name.casefold() in names:
                raise Xbox360Error("unsafe or duplicate XDVDFS filename")
            names.add(name.casefold())
            offset = self.partition + start * SECTOR
            if offset + length > self.size:
                raise Xbox360Error("XDVDFS file extends beyond the image")
            result.append(dict(name=name, offset=offset, size=length, directory=bool(attrs & 0x10)))
            pending.extend(child * 4 for child in (right, left) if child)
        return result

    def executable(self) -> tuple[bytes, dict, list[dict]]:
        entries = self.entries(self.root_sector, self.root_size)
        hit = next((e for e in entries if e['name'].casefold() == 'default.xex' and not e['directory']), None)
        if hit is None:
            raise Xbox360Error("XDVDFS disc found, but its root has no default.xex (original Xbox discs are not Xbox 360)")
        if not 24 <= hit['size'] <= MAX_EXECUTABLE:
            raise Xbox360Error("default.xex exceeds the executable size limit or is truncated")
        return self.read(hit['offset'], hit['size']), hit, entries


def xex_info(data: bytes) -> dict:
    if len(data) < 24 or data[:4] != b'XEX2':
        raise Xbox360Error("expected an Xbox 360 XEX2 executable")
    flags, payload, _, security, count = struct.unpack_from('>5I', data, 4)
    if not 24 <= payload <= len(data) or count > (payload - 24) // 8:
        raise Xbox360Error("invalid XEX2 header table")
    table_end = 24 + count * 8
    def block(at, size):
        if at < table_end or size < 0 or at + size > payload:
            raise Xbox360Error("XEX2 optional header is outside the header area")
        return data[at:at + size]
    headers = {}
    for i in range(count):
        key, value = struct.unpack_from('>II', data, 24 + i * 8)
        if key in headers:
            raise Xbox360Error("duplicate XEX2 optional header")
        headers[key] = value
        words = key & 255
        if words > 1:
            length = struct.unpack('>I', block(value, 4))[0] if words == 255 else words * 4
            if length < 4:
                raise Xbox360Error("invalid XEX2 optional header length")
            block(value, length)
    info = dict(platform='xbox360', format='XEX2', size=len(data), module_flags=flags,
                payload_offset=payload, sha256=hashlib.sha256(data).hexdigest(),
                matching_supported=False, limitation=LIMITATION)
    for key, label in ((0x10100, 'entry_point'), (0x10201, 'image_base')):
        if key in headers:
            info[label] = f"0x{headers[key]:08X}"
    if 0x3FF in headers:
        length, encryption, compression = struct.unpack('>IHH', block(headers[0x3FF], 8))
        if length < 8:
            raise Xbox360Error("truncated XEX2 file format header")
        info.update(encryption={0: 'none', 1: 'normal'}.get(encryption, f'unknown ({encryption})'),
                    compression={0: 'none', 1: 'basic', 2: 'LZX', 3: 'delta'}.get(compression, f'unknown ({compression})'))
    if 0x40006 in headers:
        execution = block(headers[0x40006], 24)
        info.update(title_id=f"{struct.unpack_from('>I', execution, 12)[0]:08X}",
                    media_id=f"{struct.unpack_from('>I', execution)[0]:08X}",
                    disc_number=execution[18], disc_count=execution[19])
    if 0x200FF in headers:
        at = headers[0x200FF]
        length = struct.unpack('>I', block(at, 4))[0]
        if (length - 4) % 16:
            raise Xbox360Error('invalid XEX2 static-library table')
        libraries = []
        for p in range(at + 4, at + length, 16):
            record = block(p, 16)
            major, minor, build, flags = struct.unpack_from('>4H', record, 8)
            libraries.append(dict(name=record[:8].split(b'\0')[0].decode('ascii', 'replace'),
                                  version=f'{major}.{minor}.{build}', flags=flags))
        info['static_libraries'] = libraries
    if security:
        sec = block(security, 0x184)
        info['image_size'] = struct.unpack_from('>I', sec, 4)[0]
    return info


def probe(src: bytes | Path) -> bool:
    """Recognize XEX2 or an Xbox disc before the generic ISO9660 reader."""
    with (Path(src).open('rb') if isinstance(src, (str, Path)) else io.BytesIO(src)) as f:
        if f.read(4) == b'XEX2':
            return True
        f.seek(0, 2)
        size = f.tell()
        for partition in PARTITIONS:
            offset = partition + 32 * SECTOR
            if offset + len(MAGIC) <= size:
                f.seek(offset)
                if f.read(len(MAGIC)) == MAGIC:
                    return True
    return False


def inspect(src: bytes | Path) -> tuple[bytes, dict]:
    with (Path(src).open('rb') if isinstance(src, (str, Path)) else io.BytesIO(src)) as f:
        head = f.read(4)
        f.seek(0)
        if head == b'XEX2':
            data = f.read(MAX_EXECUTABLE + 1)
            if len(data) > MAX_EXECUTABLE:
                raise Xbox360Error("XEX2 exceeds the executable size limit")
            return data, xex_info(data)
        disc = Disc(f)
        data, entry, entries = disc.executable()
        return data, xex_info(data) | dict(partition_offset=disc.partition, executable=entry, root_entries=entries)


def run(game: Path, output: Path | None = None, *, load_image=False, devkit=False,
        ghidra: Path | None = None, limit=100) -> dict:
    if (load_image or ghidra) and output is None:
        raise Xbox360Error('--load/--ghidra requires --output')
    data, info = inspect(game)
    image = analysis = None
    if load_image or ghidra:
        from .xex import load
        from .xbox360_analysis import functions
        image, loaded = load(data, devkit=devkit)
        info.update(loaded)
        analysis = functions(image, info)
        info['function_count'] = len(analysis['functions'])
        info['pdata_functions'] = analysis['pdata_functions']
    if output is not None:
        # A new directory prevents accidental replacement of user files or input.
        output.mkdir(parents=True, exist_ok=False)
        (output / '.gitignore').write_text('*\n', encoding='utf-8')
        (output / 'default.xex').write_bytes(data)
        if image is not None:
            (output / 'image.bin').write_bytes(image)
            (output / 'functions.json').write_text(json.dumps(analysis, indent=2) + '\n', encoding='utf-8')
        (output / 'inspection.json').write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
        if ghidra:
            from .xbox360_analysis import decompile
            report = decompile(output, ghidra, limit=limit)
            info['decompilation'] = {k: v for k, v in report.items() if k != 'results'}
            (output / 'inspection.json').write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
    return info


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Experimental Xbox 360 ISO/XEX2 loading and draft-C analysis')
    parser.add_argument('game', type=Path)
    parser.add_argument('--output', type=Path, help='new directory for default.xex and inspection.json')
    parser.add_argument('--load', action='store_true', help='decode image and discover functions')
    parser.add_argument('--devkit', action='store_true', help='use the development-kit encryption key')
    parser.add_argument('--ghidra', type=Path, help='Ghidra installation for draft-C export (implies --load)')
    parser.add_argument('--limit', type=int, default=100, help='maximum draft-C functions; 0 exports all')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args.game, args.output, load_image=args.load, devkit=args.devkit,
                             ghidra=args.ghidra, limit=args.limit), indent=2))
        return 0
    except (OSError, ValueError) as error:
        print(f'Xbox 360 import failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
