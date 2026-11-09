"""Instruction-level tests for the RXv1 processor module.

Run with:
    python -m unittest discover -s tests -v

The tests use a small IDA stub (``tests/ida_stub.py``) so the real decoders in
``rxv1.py`` can run without IDA Pro.  ``instruction_vectors.py`` contains one
regression vector per instruction variant in the processor's ``itable``.
"""

from __future__ import annotations

import sys
import unittest
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ida_stub  # noqa: E402
from instruction_vectors import VECTORS  # noqa: E402


def operand_tuple(op) -> tuple[int, int, int, int, int, int]:
    return (op.type, op.dtype, op.reg, op.value, op.addr, op.phrase)


class RxV1InstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = ida_stub.load_processor()
        cls.processor = cls.module.rxv1_processor_t()
        cls.itable = cls.processor.itable
        cls.index_by_name = {
            item["name"]: index for index, item in enumerate(cls.itable)
        }
        cls.vector_by_name = {vector[0]: vector for vector in VECTORS}

    def make_insn(self, data: bytes):
        insn = self.module.insn_t()
        insn.ea = 0
        ida_stub.set_instruction_bytes(0, data)
        return insn

    def test_instruction_table_and_vectors_cover_every_variant(self):
        table_names = [item["name"] for item in self.itable]
        vector_names = [vector[0] for vector in VECTORS]

        self.assertEqual(len(table_names), 215)
        self.assertEqual(vector_names, table_names)
        self.assertEqual(len(set(table_names)), len(table_names))

    def test_every_instruction_variant_decodes_as_recorded(self):
        for index, item in enumerate(self.itable):
            name, data_hex, size, memex, cond, expected_ops = self.vector_by_name[
                item["name"]
            ]
            data = bytes.fromhex(data_hex)
            with self.subTest(instruction=name):
                insn = self.make_insn(data)
                insn.itype = index
                item["decode"](insn)

                self.assertEqual(
                    insn.size,
                    size,
                    f"{name}: decoder reported the wrong instruction size",
                )
                self.assertEqual(insn.memex, memex, f"{name}: wrong memex")
                self.assertEqual(insn.cond, cond, f"{name}: wrong condition")
                self.assertEqual(
                    [operand_tuple(op) for op in insn.ops[: len(expected_ops)]],
                    expected_ops,
                    f"{name}: decoded operands changed",
                )
                self.assertEqual(
                    [operand_tuple(op) for op in insn.ops[len(expected_ops) :]],
                    [(0, 0, 0, 0, 0, 0)] * (len(insn.ops) - len(expected_ops)),
                    f"{name}: unexpected trailing operands",
                )

    def test_every_instruction_is_reachable_from_the_opcode_table(self):
        for index, item in enumerate(self.itable):
            name, data_hex, _, _, _, _ = self.vector_by_name[item["name"]]
            with self.subTest(instruction=name):
                insn = self.make_insn(bytes.fromhex(data_hex))
                found = self.processor.ev_ana_insn(insn)

                self.assertTrue(found, f"{name}: no table entry matched")
                selected = self.itable[insn.itype]["name"]
                self.assertEqual(
                    selected,
                    name,
                    f"{name}: opcode selected {selected!r} instead",
                )

    def test_no_unexpected_duplicate_opcode_signatures(self):
        def signature(item):
            pairs = []
            for part in range(3):
                value = item["mnem"][2 * part]
                mask = item["mnem"][2 * part + 1]
                if mask == 0:
                    break
                pairs.append((value, mask))
            return tuple(pairs)

        by_signature = defaultdict(list)
        for item in self.itable:
            by_signature[signature(item)].append(item["name"])

        duplicates = [names for names in by_signature.values() if len(names) > 1]
        self.assertEqual(duplicates, [])

    def test_all_decoder_methods_are_covered(self):
        # Every variant has a vector, so the number of distinct decoders is a
        # useful tripwire for newly added decoding code that needs review.
        table_decoders = {item["decode"].__name__ for item in self.itable}
        self.assertEqual(len(table_decoders), 78)

    def test_immediate_length_variants(self):
        # mov_6 decodes as "mov #imm, rd" with li selecting imm32/simm8/simm16/
        # simm24.  Check both the resulting size and the operand value.
        index = self.index_by_name["mov_6"]
        entry = self.itable[index]
        cases = [
            (0b00, 6, self.module.dt_dword, 0x11223344),
            (0b01, 3, self.module.dt_byte, 0x44),
            (0b10, 4, self.module.dt_word, 0x3344),
            (0b11, 5, self.module.dt_dword, 0x223344),
        ]
        for li, expected_size, expected_dtype, expected_value in cases:
            with self.subTest(li=li):
                opcode = (li << 2) | 0x02
                data = bytes([0xFB, opcode, 0x44, 0x33, 0x22, 0x11, 0, 0])
                insn = self.make_insn(data)
                insn.itype = index
                entry["decode"](insn)

                self.assertEqual(insn.size, expected_size)
                self.assertEqual(insn.Op1.type, self.module.o_imm)
                self.assertEqual(insn.Op1.dtype, expected_dtype)
                self.assertEqual(insn.Op1.value, expected_value)

                matched = self.make_insn(data)
                self.assertTrue(self.processor.ev_ana_insn(matched))
                self.assertEqual(self.itable[matched.itype]["name"], "mov_6")

    def test_branch_conditions_are_decoded(self):
        index = self.index_by_name["b_1"]
        entry = self.itable[index]
        cases = [
            (0x10, 1),  # eq
            (0x18, 2),  # ne
        ]
        for opcode, expected_cond in cases:
            with self.subTest(opcode=opcode):
                insn = self.make_insn(bytes([opcode] + [0] * 7))
                insn.itype = index
                entry["decode"](insn)
                self.assertGreater(insn.size, 0)
                self.assertEqual(insn.cond, expected_cond)

    def test_reserved_encodings_are_rejected(self):
        # Decoders signal "not my instruction" by leaving insn.size == 0.
        cases = [
            # b_2 (b<cond>.b): cd == 0x0e / 0x0f is reserved.
            ("b_2", bytes([0x2E, 0x00])),
            # clrpsw/setpsw: cb 4..7 and 9 are reserved.
            ("clrpsw", bytes([0x7F, 0xB4])),
            # mvtc_2: cr == 1, cr 4..7, and cr > 13 are reserved.
            ("mvtc_2", bytes([0xFD, 0x68, 0x01])),
            # movu_4: ad < 2 is not a valid addressing mode.
            ("movu_4", bytes([0xFD, 0x30, 0x00, 0x00])),
            # mvfachi: imm == 1 is reserved.
            ("mvfachi", bytes([0xFD, 0x1E, 0x40, 0x00])),
            # mov_1: sz == 3 is reserved.
            ("mov_1", bytes([0xB0, 0x00, 0x00, 0x00])),
        ]
        for name, data in cases:
            with self.subTest(instruction=name):
                insn = self.make_insn(data)
                insn.itype = self.index_by_name[name]
                self.itable[insn.itype]["decode"](insn)
                self.assertEqual(insn.size, 0)

    def test_phrase_operands_cover_all_addressing_forms(self):
        expected = {
            "mov_10": self.module.PHRASE_R_R,
            "mov_14_15": self.module.PHRASE_R_MINUS,
            "popm": self.module.PHRASE_R_RANGE,
        }
        for name, phrase in expected.items():
            with self.subTest(instruction=name):
                _, data_hex, _, _, _, _ = self.vector_by_name[name]
                insn = self.make_insn(bytes.fromhex(data_hex))
                insn.itype = self.index_by_name[name]
                self.itable[insn.itype]["decode"](insn)
                phrases = [
                    op.phrase for op in insn.ops if op.type == self.module.o_phrase
                ]
                self.assertIn(phrase, phrases)

        # [reg+] only appears for ad == 2 in the movu.?? addressing forms.
        index = self.index_by_name["movu_4"]
        insn = self.make_insn(bytes([0xFD, 0x38, 0x00, 0x00]))
        insn.itype = index
        self.itable[index]["decode"](insn)
        self.assertEqual(insn.Op1.type, self.module.o_phrase)
        self.assertEqual(insn.Op1.phrase, self.module.PHRASE_R_PLUS)


if __name__ == "__main__":
    unittest.main()
