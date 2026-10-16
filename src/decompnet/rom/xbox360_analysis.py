"""Xbox 360 function discovery and optional Ghidra draft-C export."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess

from .xbox360 import Xbox360Error


def functions(image: bytes, info: dict) -> dict:
    """Read CE runtime entries and discover direct branch-with-link targets.

    Pdata supplies bounds. Branch targets are candidates, not proven functions;
    no invented end address is assigned to them.
    """
    base = info['pe']['image_base']
    sections = info['pe']['sections']
    code = [s for s in sections if s['executable'] and s['size']]
    def in_code(address, size=4):
        return size > 0 and address % 4 == 0 and any(
            base + s['rva'] <= address and address + size <= base + s['rva'] + s['size'] for s in code)
    found, rejected = {}, 0
    for s in sections:
        if s['name'] != '.pdata':
            continue
        if s['size'] % 8:
            raise Xbox360Error('truncated runtime function table')
        for at in range(s['rva'], s['rva'] + s['size'], 8):
            address, packed = struct.unpack_from('>II', image, at)
            size = ((packed >> 8) & 0x3fffff) * 4
            prologue = (packed & 255) * 4
            if not packed & 0x40000000 or not in_code(address, size) or prologue > size or address in found:
                rejected += 1
                continue
            found[address] = dict(address=address, size=size, source='pdata',
                                  prologue_size=prologue, exception_handler=bool(packed & 0x80000000))
    bounded = list(found.values())
    candidates = {int(info.get('entry_point', hex(base + info['pe']['entry_rva'])), 16)}
    for s in code:
        for at in range(s['rva'], s['rva'] + s['size'] - 3, 4):
            word = struct.unpack_from('>I', image, at)[0]
            if word >> 26 == 18 and word & 1:
                displacement = word & 0x03fffffc
                if displacement & 0x02000000:
                    displacement -= 0x04000000
                target = (displacement if word & 2 else base + at + displacement) & 0xffffffff
                if in_code(target):
                    candidates.add(target)
    # Do not split known functions at local branch-with-link instructions.
    bounded.sort(key=lambda f: f['address'])
    import bisect
    starts = [f['address'] for f in bounded]
    for address in sorted(candidates):
        i = bisect.bisect_right(starts, address) - 1
        if in_code(address) and not (i >= 0 and address < starts[i] + bounded[i]['size']):
            found[address] = dict(address=address, size=None, source='call_target')
    return dict(functions=[dict(name=f'sub_{a:08X}', **f) for a, f in sorted(found.items())],
                rejected_pdata_entries=rejected, pdata_functions=len(bounded),
                limitations=['Call targets are candidates; indirect-only functions may be missing.',
                             'Generic Ghidra PowerPC has no complete Xenon VMX128 semantics.'])


def decompile(output: Path, ghidra: Path, *, limit: int = 100, timeout: int = 1800) -> dict:
    """Run an explicit local Ghidra installation; keep the project for follow-up."""
    if limit < 0:
        raise Xbox360Error('function limit must be nonnegative (0 means all)')
    output = output.resolve()
    launcher = ghidra.resolve() / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')
    if not launcher.is_file():
        raise Xbox360Error(f'Ghidra launcher not found: {launcher}')
    info = json.loads((output / 'inspection.json').read_text(encoding='utf-8'))
    project = output / 'ghidra'
    project.mkdir(exist_ok=True)
    if (project / 'xbox360.gpr').exists():
        raise Xbox360Error('Ghidra project already exists; choose a new output directory')
    scripts = Path(__file__).resolve().parents[1] / 'forks' / 'ghidra_scripts'
    command = [str(launcher), str(project), 'xbox360', '-import', str(output / 'image.bin'),
               '-loader', 'BinaryLoader', '-loader-baseAddr', f"{info['pe']['image_base']:x}",
               '-processor', 'PowerPC:BE:64:64-32addr', '-cspec', 'default', '-noanalysis',
               '-scriptPath', str(scripts), '-postScript', 'DecompWtfXbox360.java', str(output), str(limit)]
    with (output / 'ghidra.log').open('w', encoding='utf-8') as log:
        try:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise Xbox360Error('Ghidra timed out; partial results and log retained') from exc
    report = output / 'decompilation.json'
    if result.returncode or not report.is_file():
        raise Xbox360Error('Ghidra export failed; see ghidra.log')
    return json.loads(report.read_text(encoding='utf-8'))
