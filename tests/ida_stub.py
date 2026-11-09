"""Minimal fake IDA runtime used to exercise rxv1.py outside IDA Pro.

The real module imports dozens of names from the ``ida_*`` modules and only
makes sense inside IDA.  This stub provides exactly enough of those names to
import the processor module and run its instruction decoders.  It is *not* a
replacement for testing inside IDA: output formatting, xrefs and database
side effects are outside its scope.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RX_MEMORY: dict[int, int] = {}


class op_t:
    def __init__(self) -> None:
        # The processor module monkey-patches these backing fields; set them
        # before any property (phrase/memex) is touched.
        self.specval = 0
        self.specflag1 = 0
        self.type = 0
        self.dtype = 0
        self.reg = 0
        self.value = 0
        self.addr = 0
        self.phrase = 0
        self.n = 0
        self.offb = 0


class insn_t:
    def __init__(self) -> None:
        self.ea = 0
        self.size = 0
        self.itype = 0
        self.auxpref = 0
        self.insnpref = 0
        self.ops = [op_t() for _ in range(8)]
        self.Op1, self.Op2, self.Op3 = self.ops[0], self.ops[1], self.ops[2]

    def __getitem__(self, index: int) -> op_t:
        return self.ops[index]

    def __setitem__(self, index: int, value: op_t) -> None:
        self.ops[index] = value


class outctx_t:
    pass


class processor_t:
    def __init__(self) -> None:
        pass


def _get_wide_byte(ea: int) -> int:
    return RX_MEMORY[ea ^ 3]


def _noop(*_args, **_kwargs):
    return 0


# Values only need to be distinct/usable; the processor module treats them as
# opaque constants from IDA.
_CONSTANTS = {
    # processor flags
    "PR_SEGS": 0x0001,
    "PR_RNAMESOK": 0x0002,
    "PR_WORD_INS": 0x0004,
    "PR_USE32": 0x0008,
    "PR_DEFSEG32": 0x0010,
    "PR_BINMEM": 0x0020,
    "PRN_HEX": 0x0040,
    # assembler
    "AS_COLON": 0x0001,
    "AS_ASCIIZ": 0x0002,
    "AS_ASCIIC": 0x0004,
    "AS_1TEXT": 0x0008,
    # operand types
    "o_void": 0,
    "o_reg": 1,
    "o_mem": 2,
    "o_phrase": 3,
    "o_displ": 4,
    "o_imm": 5,
    "o_near": 6,
    "o_flag": 7,
    "o_creg": 8,
    "o_slsb": 9,
    "o_adest": 10,
    "o_idpspec0": 11,
    "o_idpspec1": 12,
    "o_idpspec2": 13,
    "o_idpspec3": 14,
    # data types
    "dt_byte": 1,
    "dt_word": 2,
    "dt_dword": 4,
    "dt_code": 8,
    # canonical features
    "CF_STOP": 0x0001,
    "CF_USE1": 0x0002,
    "CF_CHG1": 0x0004,
    "CF_USE2": 0x0008,
    "CF_CHG2": 0x0010,
    "CF_USE3": 0x0020,
    "CF_CHG3": 0x0040,
    "CF_JUMP": 0x0080,
    "CF_CALL": 0x0100,
    "CF_SHFT": 0x0200,
    # misc
    "BADADDR": 0xFFFFFFFFFFFFFFFF,
    "COLOR_ERROR": 0,
    "COLOR_INSN": 0,
    "COLOR_RPTCMT": 0,
    "OOFW_IMM": 0,
    "OOFW_32": 0,
    "OOFS_NOSIGN": 0,
    "OOF_NUMBER": 0,
    "OOF_SIGNED": 0,
    "PR_NONAME": 0,
    "PR_JUMP": 0,
    "fl_CN": 0,
    "fl_JN": 0,
    "fl_F": 0,
    "dr_O": 0,
    "SN_NOWARN": 0,
    "SN_LOCAL": 0,
    "REF_OFF32": 0,
    "CF_USE1": 0x0002,
}

# The module uses ida_ua.insn_t in an annotation after `from ida_ua import *`.
# Real IDAPython exposes the module name as an attribute; mirror that here.
_STUB = None


def _make_stub() -> types.ModuleType:
    global _STUB
    module = types.ModuleType("ida_stub")

    for name, value in _CONSTANTS.items():
        setattr(module, name, value)

    module.insn_t = insn_t
    module.op_t = op_t
    module.outctx_t = outctx_t
    module.processor_t = processor_t
    module.get_wide_byte = _get_wide_byte
    module.get_byte = _get_wide_byte

    # Functions used by the module at runtime (only the no-op behaviour is
    # needed for decoding tests).
    for name in (
        "add_cref", "add_dref", "decode_prev_insn", "remember_problem",
        "op_offset", "op_num", "op_flt", "set_cmt", "set_name",
        "get_flags", "op_adds_xrefs", "add_segm", "inf_set_be", "getsysfile",
    ):
        setattr(module, name, _noop)

    module.getsysfile = lambda *_args, **_kwargs: None
    module.add_segm = _noop
    module.CFG_SUBDIR = 0
    # rxv1.py uses `ida_ua.insn_t` in a runtime-evaluated annotation after a
    # star import, so `ida_ua` must also be exported by the star import.
    module.ida_ua = module
    module.ida_bytes = module
    module.ida_ida = module
    module.ida_segment = module
    module.ida_xref = module
    module.idaapi = module
    module.idc = module
    module.ida_pro = module
    module.__all__ = [name for name in module.__dict__ if not name.startswith("_")]
    _STUB = module
    return module


def install() -> types.ModuleType:
    """Register the fake ida_* modules in sys.modules (idempotent)."""
    global _STUB
    if _STUB is not None:
        return _STUB

    stub = _make_stub()
    for module_name in (
        "ida_ua", "ida_idp", "ida_auto", "ida_nalt", "ida_funcs",
        "ida_lines", "ida_problems", "ida_segment", "ida_name",
        "ida_netnode", "ida_xref", "ida_idaapi", "ida_bytes", "ida_ida",
        "ida_frame", "ida_offset", "ida_pro", "idc", "idaapi",
    ):
        sys.modules[module_name] = stub
    return stub


def load_processor():
    """Import rxv1.py with the stub installed and return the processor class."""
    install()
    spec = importlib.util.spec_from_file_location(
        "rxv1_under_test", REPO_ROOT / "rxv1.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load rxv1.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def set_instruction_bytes(ea: int, data: bytes) -> None:
    """Put an instruction at *ea* using the byte order expected by rxv1.py.

    rxv1.get_hl_byte(ea) calls ida_bytes.get_wide_byte(ea ^ 3); the stub maps
    that back to RX_MEMORY so a natural byte string can be supplied here.
    """
    for offset, byte in enumerate(data):
        RX_MEMORY[ea + offset] = byte
