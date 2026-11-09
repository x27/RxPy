"""Encoding tests for RXv2 new/extended instruction forms.

These vectors are taken from the instruction-code tables in sw2.pdf rather than
generated from the current implementation, so they catch opcode-table mistakes
that the regression vectors cannot.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ida_stub  # noqa: E402


class RxV2ExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = ida_stub.load_processor()
        cls.processor = cls.module.rxv1_processor_t()
        cls.index_by_name = {
            item["name"]: index for index, item in enumerate(cls.processor.itable)
        }

    def decode(self, name: str, data: bytes):
        insn = self.module.insn_t()
        insn.ea = 0
        insn.itype = self.index_by_name[name]
        ida_stub.set_instruction_bytes(0, data + bytes(16))
        self.processor.itable[insn.itype]["decode"](insn)
        return insn

    def analyze(self, data: bytes):
        insn = self.module.insn_t()
        insn.ea = 0
        ida_stub.set_instruction_bytes(0, data + bytes(16))
        self.assertTrue(self.processor.ev_ana_insn(insn))
        return self.processor.itable[insn.itype]["name"], insn

    def test_dsp_adest_encodings(self):
        # sw2.pdf pages 249/250/263/264: opcode byte 1 is
        # 04/05/00/02/01 plus the Adest selector in bit 3.
        cases = [
            ("machi", 0x04),
            ("maclh", 0x06),
            ("maclo", 0x05),
            ("mulhi", 0x00),
            ("mullh", 0x02),
            ("mullo", 0x01),
        ]
        for name, opcode in cases:
            for adest in (0, 1):
                with self.subTest(instruction=name, adest=adest):
                    data = bytes([0xFD, opcode | (adest << 3), 0x12])
                    selected, insn = self.analyze(data)
                    self.assertEqual(selected, name)
                    self.assertEqual(insn.size, 3)
                    self.assertEqual(insn.Op1.type, self.module.o_reg)
                    self.assertEqual(insn.Op1.reg, 1)
                    self.assertEqual(insn.Op2.type, self.module.o_reg)
                    self.assertEqual(insn.Op2.reg, 2)
                    self.assertEqual(insn.Op3.type, self.module.o_adest)
                    self.assertEqual(insn.Op3.value, adest)

    def test_accumulator_rounding_encodings(self):
        # sw2.pdf page 278/279: RACL/RDACL use opcode 19, RACW/RDACW use 18.
        # The Adest selector is bit 7 and IMM:1 is bit 4 of the third byte.
        cases = [
            ("racl", 0x19, 0x00),
            ("rdacl", 0x19, 0x40),
            ("racw_2", 0x18, 0x00),
            ("rdacw", 0x18, 0x40),
        ]
        for name, opcode, fixed in cases:
            for adest in (0, 1):
                for imm2 in (False, True):
                    with self.subTest(name=name, adest=adest, imm2=imm2):
                        third = fixed | (adest << 7) | (0x10 if imm2 else 0)
                        data = bytes([0xFD, opcode, third])
                        selected, insn = self.analyze(data)
                        self.assertEqual(selected, name)
                        self.assertEqual(insn.size, 3)
                        self.assertEqual(insn.Op1.type, self.module.o_imm)
                        self.assertEqual(insn.Op1.value, 2 if imm2 else 1)
                        self.assertEqual(insn.Op2.type, self.module.o_adest)
                        self.assertEqual(insn.Op2.value, adest)

    def test_accumulator_move_imm2_encodings(self):
        # sw2.pdf page 265/266: imm[1] is bit 0 of byte 1, imm[0] is bit 6
        # of byte 2, and Adest is bit 7.  The encoded mapping is
        # 00->2, 01->reserved, 10->0, 11->1.
        cases = [
            ("mvfachi", 0x00),
            ("mvfacmi", 0x20),
        ]
        for name, fixed_byte2 in cases:
            for raw_imm, expected_imm in ((0, 2), (2, 0), (3, 1)):
                with self.subTest(instruction=name, raw_imm=raw_imm):
                    data = bytes([
                        0xFD,
                        0x1E | ((raw_imm >> 1) & 1),
                        fixed_byte2 | ((raw_imm & 1) << 6) | (1 << 7),
                    ])
                    selected, insn = self.analyze(data)
                    self.assertEqual(selected, name)
                    self.assertEqual(insn.Op1.type, self.module.o_imm)
                    self.assertEqual(insn.Op1.value, expected_imm)
                    self.assertEqual(insn.Op2.type, self.module.o_adest)
                    self.assertEqual(insn.Op2.value, 1)

    def test_stz_and_stnz_register_forms(self):
        # Verified against rx-elf-as --misa=v2.
        cases = [
            ("stz_2", bytes([0xFC, 0x4B, 0x12])),
            ("stnz_2", bytes([0xFC, 0x4F, 0x12])),
        ]
        for name, data in cases:
            with self.subTest(instruction=name):
                selected, insn = self.analyze(data)
                self.assertEqual(selected, name)
                self.assertEqual(
                    [(op.type, op.reg) for op in insn.ops[:2]],
                    [(self.module.o_reg, 1), (self.module.o_reg, 2)],
                )

    def test_extb_is_accepted_by_control_register_instructions(self):
        cases = [
            ("popc", bytes([0x7E, 0xED])),
            ("pushc", bytes([0x7E, 0xCD])),
            ("mvfc", bytes([0xFD, 0x6A, 0xD0])),
            ("mvtc_2", bytes([0xFD, 0x68, 0x0D])),
            ("mvtc_1", bytes([0xFD, 0x73, 0x0D]) + bytes(4)),
        ]
        for name, data in cases:
            with self.subTest(instruction=name):
                insn = self.decode(name, data)
                self.assertGreater(insn.size, 0)
                cregs = [
                    op.value for op in insn.ops if op.type == self.module.o_creg
                ]
                self.assertEqual(cregs, [13])  # EXTB


if __name__ == "__main__":
    unittest.main()
