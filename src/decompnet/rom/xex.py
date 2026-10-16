"""Bounded XEX2 image loader. Format reference: Xenia xex_module.cc.

The result is a memory image, not an on-disk PE. Only uncompressed and basic
compression are supported. No signature/authenticity verification is performed.
"""
from __future__ import annotations

import struct
from .xbox360 import MAX_EXECUTABLE, Xbox360Error, xex_info

RETAIL_KEY = bytes.fromhex('20b185a59d28fdc340583fbb0896bf91')


def load(data: bytes, *, devkit: bool = False) -> tuple[bytes, dict]:
    info = xex_info(data)
    security, count = struct.unpack_from('>II', data, 16)
    headers = dict(struct.unpack_from('>II', data, 24 + i * 8) for i in range(count))
    if not security or 0x3ff not in headers:
        raise Xbox360Error('XEX security and file-format headers are required')
    size = info['image_size']
    if not 64 <= size <= MAX_EXECUTABLE:
        raise Xbox360Error('invalid XEX image size')
    at = headers[0x3ff]
    length, encryption, compression = struct.unpack_from('>IHH', data, at)
    if encryption not in (0, 1) or compression not in (0, 1):
        raise Xbox360Error('loading currently supports only none/basic compression and none/AES encryption')
    payload = data[info['payload_offset']:]
    if compression == 1:
        if length < 16 or (length - 8) % 8:
            raise Xbox360Error('invalid basic compression block table')
        blocks = [struct.unpack_from('>II', data, p) for p in range(at + 8, at + length, 8)]
    else:
        blocks = [(min(size, len(payload)), 0)]
    expanded = sum(n + z for n, z in blocks)
    consumed = sum(n for n, _ in blocks)
    if expanded > size or consumed > len(payload) or len(payload) - consumed > 15:
        raise Xbox360Error('basic compression extents disagree with image/payload size')
    if encryption:
        if any(n % 16 for n, _ in blocks):
            raise Xbox360Error('encrypted data blocks must be AES aligned')
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError as exc:
            raise Xbox360Error('install decompnet[xbox360] for AES loading') from exc
        def decrypt(key, ciphertext):
            ctx = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
            return ctx.update(ciphertext) + ctx.finalize()
        key = decrypt(bytes(16) if devkit else RETAIL_KEY, data[security + 0x150:security + 0x160])
        payload = decrypt(key, payload[:consumed])
    image = bytearray(size)
    source = target = 0
    for n, zero in blocks:
        image[target:target + n] = payload[source:source + n]
        source += n
        target += n + zero
    pe = parse_pe(image)
    if info.get('image_base') and int(info['image_base'], 16) != pe['image_base']:
        raise Xbox360Error('XEX and PE image bases disagree')
    return bytes(image), info | {'pe': pe, 'loaded': True}


def parse_pe(image: bytes) -> dict:
    def bound(at, size):
        if at < 0 or at + size > len(image):
            raise Xbox360Error('PE structure extends beyond the image')
    bound(0, 64)
    if image[:2] != b'MZ':
        raise Xbox360Error('decoded image has no MZ header; check retail/devkit key')
    nt = struct.unpack_from('<I', image, 60)[0]
    bound(nt, 24)
    if image[nt:nt + 4] != b'PE\0\0':
        raise Xbox360Error('invalid decoded PE signature')
    machine, count = struct.unpack_from('<HH', image, nt + 4)
    optional_size = struct.unpack_from('<H', image, nt + 20)[0]
    opt = nt + 24
    bound(opt, optional_size + count * 40)
    if machine != 0x1f2 or optional_size < 96 or struct.unpack_from('<H', image, opt)[0] != 0x10b:
        raise Xbox360Error('expected a PowerPC big-endian PE32 executable')
    base = struct.unpack_from('<I', image, opt + 28)[0]
    sections = []
    for i in range(count):
        p = opt + optional_size + 40 * i
        name = bytes(image[p:p + 8]).split(b'\0')[0].decode('ascii', 'replace')
        vsize, rva, rawsize, rawptr = struct.unpack_from('<4I', image, p + 8)
        flags = struct.unpack_from('<I', image, p + 36)[0]
        # XEX conversion can strip discardable PE relocation/debug sections.
        declared_size = vsize
        if rva + vsize > len(image) and flags & 0x02000000:
            vsize = max(0, len(image) - rva)
        bound(min(rva, len(image)) if not vsize else rva, vsize)
        if base + rva + vsize > 0x100000000:
            raise Xbox360Error('PE section address overflow')
        if any(rva < s['rva'] + s['size'] and s['rva'] < rva + vsize for s in sections):
            raise Xbox360Error('overlapping PE sections')
        sections.append(dict(name=name, rva=rva, size=vsize, declared_size=declared_size, raw_size=rawsize,
                             raw_offset=rawptr, flags=flags, executable=bool(flags & 0x20000000)))
    return dict(image_base=base, entry_rva=struct.unpack_from('<I', image, opt + 16)[0],
                linker_version=f'{image[opt + 2]}.{image[opt + 3]}', sections=sections)


def disk_pe(image: bytes, metadata: dict) -> bytes:
    """Repack memory sections at their declared raw offsets for PE importers."""
    sections = metadata['pe']['sections']
    end = max((s['raw_offset'] + s['raw_size'] for s in sections), default=0)
    if not 64 <= end <= MAX_EXECUTABLE:
        raise Xbox360Error('invalid PE file extent')
    nt = struct.unpack_from('<I', image, 60)[0]
    header_size = struct.unpack_from('<I', image, nt + 24 + 60)[0]
    if not 64 <= header_size <= min(len(image), end):
        raise Xbox360Error('invalid PE header size')
    out = bytearray(end)
    out[:header_size] = image[:header_size]
    extents = [(0, header_size)]
    for s in sections:
        start, n = s['raw_offset'], s['raw_size']
        if not n:
            continue
        if any(start < b and a < start + n for a, b in extents):
            raise Xbox360Error('overlapping raw PE extents')
        extents.append((start, start + n))
        copy = min(n, s['size'])
        out[start:start + copy] = image[s['rva']:s['rva'] + copy]
    return bytes(out)
