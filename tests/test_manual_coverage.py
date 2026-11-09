"""Check rxv1.py against the instruction lists in sw.pdf and sw2.pdf.

sw.pdf (Renesas R01US0032EJ0130, RXv1) states that RXv1 has 90 instructions.
sw2.pdf (Renesas R01US0071EJ0100, RXv2) states that RXv2 has 109 instructions:
the RXv1 set plus 19 new ones.  These lists are recorded explicitly so an
accidentally missing instruction family fails the test suite instead of only
being noticed during a manual review.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ida_stub  # noqa: E402

# Section 3.1, "List of Instructions", of sw.pdf.
MANUAL_INSTRUCTIONS = {
    "ABS", "ADC", "ADD", "AND", "BCLR", "BCnd", "BMCnd", "BNOT",
    "BRA", "BRK", "BSET", "BSR", "BTST", "CLRPSW", "CMP", "DIV",
    "DIVU", "EMUL", "EMULU", "FADD", "FCMP", "FDIV", "FMUL", "FSUB",
    "FTOI", "INT", "ITOF", "JMP", "JSR", "MACHI", "MACLO", "MAX",
    "MIN", "MOV", "MOVU", "MUL", "MULHI", "MULLO", "MVFACHI",
    "MVFACMI", "MVFC", "MVTACHI", "MVTACLO", "MVTC", "MVTIPL",
    "NEG", "NOP", "NOT", "OR", "POP", "POPC", "POPM", "PUSH",
    "PUSHC", "PUSHM", "RACW", "REVL", "REVW", "RMPA", "ROLC",
    "RORC", "ROTL", "ROTR", "ROUND", "RTE", "RTFI", "RTS", "RTSD",
    "SAT", "SATR", "SBB", "SCCnd", "SCMPU", "SETPSW", "SHAR",
    "SHLL", "SHLR", "SMOVB", "SMOVF", "SMOVU", "SSTR", "STNZ",
    "STZ", "SUB", "SUNTIL", "SWHILE", "TST", "WAIT", "XCHG", "XOR",
}

# Section 3.2.1, "RXv2 Newly Added Instructions", of sw2.pdf.
RXV2_NEW_INSTRUCTIONS = {
    "FSQRT", "FTOU", "UTOF", "MOVCO", "MOVLI", "EMACA", "EMSBA",
    "EMULA", "MACLH", "MSBHI", "MSBLH", "MSBLO", "MULLH",
    "MVFACGU", "MVFACLO", "MVTACGU", "RACL", "RDACL", "RDACW",
}

RXV2_INSTRUCTIONS = MANUAL_INSTRUCTIONS | RXV2_NEW_INSTRUCTIONS

# The processor module uses one entry for the whole conditional family.
FAMILY_ALIASES = {"BCnd": "b", "BMCnd": "bm", "SCCnd": "sc"}

# Families in rxv1.py that are in neither the RXv1 nor RXv2 manual
# (RXv3 additions).
KNOWN_EXTRA_FAMILIES = {"bfmov", "bfmovz"}

# BCnd/BMCnd/SCCnd condition suffixes in the manual, mapped to cond_names.
MANUAL_CONDITIONS = {
    "eq": "eq", "z": "eq", "ne": "ne", "nz": "ne", "c": "c",
    "nc": "nc", "gtu": "gtu", "leu": "leu", "pz": "pz", "n": "n",
    "ge": "ge", "lt": "lt", "gt": "gt", "le": "le", "o": "o",
    "no": "no",
}


class ManualCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = ida_stub.load_processor()
        cls.processor = cls.module.rxv1_processor_t()
        cls.implemented = {
            item["name"].split("_")[0].split(".")[0]
            for item in cls.processor.itable
        }

    def test_manual_lists_90_rxv1_and_109_rxv2_instructions(self):
        self.assertEqual(len(MANUAL_INSTRUCTIONS), 90)
        self.assertEqual(len(RXV2_NEW_INSTRUCTIONS), 19)
        self.assertEqual(len(RXV2_INSTRUCTIONS), 109)

    def test_all_rxv1_instruction_families_are_implemented(self):
        expected = {
            FAMILY_ALIASES.get(name, name).lower()
            for name in MANUAL_INSTRUCTIONS
        }
        self.assertEqual(expected - self.implemented, set())

    def test_all_rxv2_instruction_families_are_implemented(self):
        expected = {
            FAMILY_ALIASES.get(name, name).lower()
            for name in RXV2_INSTRUCTIONS
        }
        self.assertEqual(expected - self.implemented, set())

    def test_only_known_non_rxv1_rxv2_families_are_extra(self):
        expected = {
            FAMILY_ALIASES.get(name, name).lower()
            for name in RXV2_INSTRUCTIONS
        }
        self.assertEqual(self.implemented - expected, KNOWN_EXTRA_FAMILIES)

    def test_all_manual_condition_suffixes_are_supported(self):
        for suffix, canonical in MANUAL_CONDITIONS.items():
            with self.subTest(suffix=suffix):
                self.assertIn(canonical, self.module.cond_names[:14])


if __name__ == "__main__":
    unittest.main()
