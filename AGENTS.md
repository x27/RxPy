# AGENTS.md

## What this repo is

Single-file IDA Pro processor module (`rxv1.py`) for the Renesas RXv1 architecture, big-endian, targeting IDA Pro 9.2. There is no package, build system, or CI. Decoding is tested outside IDA with stubs; output formatting, xrefs, and database side effects still require IDA.

## Verification

- Decoder tests: `python -m unittest discover -s tests -v` (standard library only, Python 3.10+).
  - `tests/ida_stub.py` fakes the `ida_*` modules so `rxv1.py` can be imported and decoded outside IDA.
  - `tests/instruction_vectors.py` is a generated regression fixture with one vector for every `itable` variant. Regenerate it only after intentional decoder/table changes: `python tests/generate_vectors.py`, then review the diff.
  - `tests/test_manual_coverage.py` records the 90-instruction RXv1 list from `sw.pdf` and the 109-instruction RXv2 list from `sw2.pdf`, then fails on missing families or condition suffixes. Treat those PDFs as the ISA source of truth; only BFMOV/BFMOVZ are RXv3 additions beyond them.
- Syntax only: `python -m py_compile rxv1.py`.
- Real verification: copy `rxv1.py` into IDA's `procs/` directory, start IDA 9.2, load a big-endian RX binary, and inspect disassembly. Importing the file outside IDA without the stub fails because `ida_*` modules are unavailable.

## Architecture / editing map

- `rxv1_processor_t` is the entire module; `PROCESSOR_ENTRY()` at the end instantiates it for IDA.
- Instruction definitions live in `self.itable` in `init_instructions()`. Each item is `{name, mnem, decode, feature, group}`.
  - `mnem` is three little `[value, mask]` pairs: `[v0, m0, v1, m1, v2, m2]`. Matching stops early when a mask is `0x00`; `ev_ana_insn` scans the table linearly.
  - `name` is `base_variant` (e.g. `mov_10`). The part before `_` becomes the IDA mnemonic and the generated `itype_<base>` attribute; variants intentionally share a base.
  - `decode` is a `decode_b*` method. It must set `insn.size`; returning with `insn.size == 0` rejects the match.
- `RX_GROUP_*` constants feed semantic analysis, operand rendering, and data/call-reference heuristics in `ev_emu_insn`; add new constants at the end and wire them in `get_itype_group` usage.
- Register, coprocessor-register, and flag name tables are in `init_registers()`. They are index-aligned and `init_registers` derives `ireg_*` attributes, so append carefully.
- Custom operand types use `o_idpspec0..3`: `o_flag`, `o_creg`, `o_slsb`, `o_adest`; rendering is centralized in `ev_out_operand`.

## Gotchas

- Instruction bytes must be read through `get_hl_byte` / `get_hl_word` / `get_hl_bits24` / `get_hl_dword`. They reverse byte order (`ea ^ 3` for bytes); do not replace them with direct `ida_bytes` reads or the RX big-endian encoding breaks.
- `MEMEX_NEED_SHOW` (bit 16) must be OR-ed into a memex value when the `.b/.w/.l/...` suffix should be printed; the low 3 bits select `memex_names`.
- `memex`, `cond`, `phrase`, and `op_t.memex` are monkey-patched properties over IDA fields (`auxpref`, `insnpref`, `specval`, `specflag1`); reuse these instead of adding new ad-hoc bitfields.
- `ev_emu_insn` contains pattern-matching heuristics that look at the previous/previous-previous instruction (e.g. `mov.l #imm, reg` before `jsr`, loads, and `mvtc #imm, intb`). Changes to decoder operand layout or instruction size can break these silently; check this function when altering decoders.
- `ev_newbinary` hardcodes RX memory segments; `notify_init` forces big-endian mode and looks for an optional `RXv1.cfg` system file.

## Conventions

- Keep decoder names descriptive of the operand form (`decode_b3_mi_ld_rs_rd`, etc.) and one table entry per ISA variant.
- Commit messages in history use short `fix:`/`add`/`refactoring` style; no branch or release process is documented.
