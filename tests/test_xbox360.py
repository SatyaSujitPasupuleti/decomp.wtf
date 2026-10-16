"""Synthetic fixtures only: no commercial game bytes or SDK required."""
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from decompnet.rom import detect, xbox360 as xb


def executable():
    data = bytearray(0x110)
    struct.pack_into('>4s5I', data, 0, b'XEX2', 1, 0x100, 0, 0, 3)
    struct.pack_into('>6I', data, 24, 0x3FF, 0x40, 0x40006, 0x50, 0x10100, 0x82001000)
    struct.pack_into('>IHH', data, 0x40, 8, 1, 1)
    struct.pack_into('>I', data, 0x5C, 0x12345678)
    data[0x62:0x64] = b'\x01\x01'
    return bytes(data)


def disc(partition=0, name=b'default.xex'):
    data = bytearray(partition + 36 * xb.SECTOR)
    # Xbox discs may expose an ISO9660 video partition too.
    data[32769:32774] = b'CD001'
    descriptor = partition + 32 * xb.SECTOR
    data[descriptor:descriptor + 20] = xb.MAGIC
    data[descriptor + xb.SECTOR - 20:descriptor + xb.SECTOR] = xb.MAGIC
    struct.pack_into('<II', data, descriptor + 20, 33, xb.SECTOR)
    root = partition + 33 * xb.SECTOR
    struct.pack_into('<HHIIBB', data, root, 0, 0, 34, len(executable()), 0, len(name))
    data[root + 14:root + 14 + len(name)] = name
    start = partition + 34 * xb.SECTOR
    data[start:start + len(executable())] = executable()
    return bytes(data)


class Xbox360Tests(unittest.TestCase):
    def test_xbox_precedes_iso9660(self):
        picked = detect.identify(disc())
        self.assertEqual(picked.platform, 'xbox360')
        self.assertEqual(picked.data, executable())
        self.assertFalse(picked.info['matching_supported'])

    def test_partition_and_case_insensitive_name(self):
        data, info = xb.inspect(disc(0xFB20, b'DEFAULT.XEX'))
        self.assertEqual(data, executable())
        self.assertEqual(info['partition_offset'], 0xFB20)

    def test_xex_metadata(self):
        picked = detect.identify(executable())
        self.assertEqual(picked.info['title_id'], '12345678')
        self.assertEqual(picked.info['encryption'], 'normal')
        self.assertEqual(picked.info['compression'], 'basic')
        self.assertEqual(picked.info['entry_point'], '0x82001000')

    def test_missing_default(self):
        with self.assertRaisesRegex(xb.Xbox360Error, 'no default.xex'):
            xb.inspect(disc(name=b'default.xbe'))

    def test_cycle(self):
        image = bytearray(disc())
        root = 33 * xb.SECTOR
        struct.pack_into('<H', image, root, 8)
        image[root + 32:root + 57] = image[root:root + 25]
        image[root + 46:root + 57] = b'another.xex'
        with self.assertRaisesRegex(xb.Xbox360Error, 'cyclic'):
            xb.inspect(image)

    def test_invalid_extent(self):
        image = bytearray(disc())
        struct.pack_into('<I', image, 33 * xb.SECTOR + 4, 0xFFFFFFFF)
        with self.assertRaisesRegex(xb.Xbox360Error, 'beyond'):
            xb.inspect(image)

    def test_truncated_and_bad_optional_headers(self):
        for image in (b'XEX2', executable()[:60]):
            with self.assertRaises(xb.Xbox360Error):
                xb.xex_info(image)
        data = bytearray(executable())
        struct.pack_into('>I', data, 28, 0x108)
        with self.assertRaisesRegex(xb.Xbox360Error, 'outside'):
            xb.xex_info(data)

    def test_corrupt_descriptor_no_psx_fallback(self):
        image = bytearray(disc())
        image[33 * xb.SECTOR - 1] = 0
        with self.assertRaisesRegex(ValueError, 'damaged XDVDFS'):
            detect.identify(image)

    def test_non_xbox(self):
        self.assertFalse(xb.probe(b'ordinary file'))
        with self.assertRaises(xb.Xbox360Error):
            xb.inspect(b'ordinary file')

    def test_extract_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp) / 'game.iso', Path(tmp) / 'out'
            src.write_bytes(disc())
            xb.run(src, out)
            self.assertEqual((out / 'default.xex').read_bytes(), executable())
            self.assertEqual(json.loads((out / 'inspection.json').read_text())['format'], 'XEX2')
            self.assertEqual(src.read_bytes(), disc())
            with self.assertRaises(FileExistsError):
                xb.run(src, out)


if __name__ == '__main__':
    unittest.main()
