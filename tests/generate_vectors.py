"""Regenerate ``instruction_vectors.py`` from the current instruction table.

The vectors are regression fixtures: each one is a machine-code sample for an
`itable` entry together with the operands decoded by rxv1.py.  Re-run this
script only after intentionally changing a decoder or an instruction entry, and
review the resulting diff.

Usage:
    python tests/generate_vectors.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ida_stub  # noqa: E402

BYTE_PATTERNS = (
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
)
VECTOR_BYTES = 16


def encode(item, pattern: int) -> bytes:
    data = bytearray([pattern] * VECTOR_BYTES)
    for index in range(3):
        value = item["mnem"][2 * index]
        mask = item["mnem"][2 * index + 1]
        if mask == 0:
            break
        data[index] = (pattern & ~mask & 0xFF) | (value & mask)
    return bytes(data)


def decode_direct(processor, module, index: int, data: bytes):
    insn = module.insn_t()
    insn.ea = 0
    insn.itype = index
    ida_stub.set_instruction_bytes(0, data)
    processor.itable[index]["decode"](insn)
    return insn


def operand_tuple(op) -> tuple[int, int, int, int, int, int]:
    return (op.type, op.dtype, op.reg, op.value, op.addr, op.phrase)


def richness(insn) -> int:
    score = 0
    for op in insn.ops:
        score += sum(value != 0 for value in operand_tuple(op))
    return score


def build_vectors(processor, module):
    vectors = []
    failures = []
    for index, item in enumerate(processor.itable):
        best = None
        for pattern in BYTE_PATTERNS:
            data = encode(item, pattern)
            insn = decode_direct(processor, module, index, data)
            if not 0 < insn.size <= VECTOR_BYTES:
                continue
            score = richness(insn)
            if best is None or score > best[0]:
                best = (score, data, insn)
        if best is None:
            failures.append((index, item["name"]))
            continue
        _, data, insn = best
        ops = [operand_tuple(op) for op in insn.ops]
        # Trim trailing unused operands (o_void == 0).
        while ops and ops[-1] == (0, 0, 0, 0, 0, 0):
            ops.pop()
        vectors.append(
            (item["name"], data.hex(), insn.size, insn.memex, insn.cond, ops)
        )
    return vectors, failures


def render(vectors) -> str:
    lines = [
        '"""Generated regression vectors for every rxv1.py instruction variant.',
        "",
        "Do not edit by hand. Regenerate with: python tests/generate_vectors.py",
        '"""',
        "",
        "# (name, instruction bytes hex, size, memex, cond, decoded operands)",
        "# operand = (type, dtype, reg, value, addr, phrase)",
        "VECTORS = [",
    ]
    for name, data, size, memex, cond, ops in vectors:
        lines.append(f"    ({name!r}, {data!r}, {size}, {memex}, {cond}, {ops!r}),")
    lines.append("]")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    module = ida_stub.load_processor()
    processor = module.rxv1_processor_t()
    vectors, failures = build_vectors(processor, module)
    output = Path(__file__).with_name("instruction_vectors.py")
    output.write_text(render(vectors), encoding="utf-8")
    print(f"wrote {len(vectors)} vectors to {output}")
    for index, name in failures:
        print(f"FAILED to build a vector for [{index}] {name}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
