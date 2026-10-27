# Credits

## Upstream

This module is the ST7 processor definition from Ghidra pull request
[#3631](https://github.com/NationalSecurityAgency/ghidra/pull/3631), "ST7 processor definition",
by Alessandro Gatti ([@agatti](https://github.com/agatti)), opened 2021-11-14 against
`NationalSecurityAgency/ghidra` and never merged. It is imported at the pull request head
`8f6de1957036263f25f8304a8c78fcfec12225ed` (one squashed commit, "ST7 processor definition.",
author Alessandro Gatti <a.gatti@frob.it>). License: Apache License 2.0 (Ghidra contribution;
`LICENSE` is the Apache-2.0 text, `LICENSE.txt` is the Ghidra per-module notice that came with
the pull request). Upstream files keep their license headers; changes made here are also
licensed under Apache-2.0 and exist as commits on top of the upstream history (branch
`ghidra-rare`).

The pull request thread also credits reviewers whose comments shaped the upstream version:
[@mumbel](https://github.com/mumbel) (review of the p-code: call/goto forms, return, macros,
SLEIGH lint) and [@GhidorahRex](https://github.com/GhidorahRex) (SLEIGH pattern explanation).

### Other implementations

- No other ST7 SLEIGH module was found: GitHub repository searches for "ghidra st7", "st7
  sleigh" and "ghidra STMicroelectronics ST7 processor", and code search for `ST7` in
  `.slaspec`/`.ldefs`/`.sinc` files, return nothing besides the pull request (see also
  `community/CANDIDATES.md`: "Only implementation found").
- [esaulenka/ghidra_STM8](https://github.com/esaulenka/ghidra_STM8) (mentioned in the pull
  request thread) is an STM8 module. STM8 is a different instruction set; nothing was taken
  from it.

## Reference material

- *ST7 Family Programming Manual*, STMicroelectronics PM0002 (2005): operations, flags,
  addressing modes, opcode tables and stack order. `test/st7model.py` is a small independent
  model of the core written from its instruction tables, and the emulator cases in
  `test/emu/cases-hand.txt` were worked out from it. The PDF is not redistributed (the copy
  used was recovered with Ghostscript from the first megabyte of the Internet Archive capture
  of `st.com/resource/en/programming_manual/pm0002-st7-family-programming-manual-stmicroelectronics.pdf`,
  the file `data/manuals/ST7.idx` refers to).
- AS (Alfred Arnold's macro assembler) 1.42 Bld 315, `-cpu st7`, run as a black box: assembles
  every instruction form; the decode tests round-trip through it.
- The uCsim ST7 simulator (`ucsim_st7`, Daniel Drotos, GPL-2.0; built from the project's
  repository, commit `6f7cf7a4a67f5787a3a59847cfbd9f366a222e4b`) run as a black box: a second
  disassembler and a second implementation of the instruction semantics. Its source was not
  read. It disagrees with the manual in several documented ways; every difference class is
  listed in GHIDRA-RARE.md.
- SDCC and its ASxxxx assemblers have no ST7 target (SDCC has STM8, a different instruction
  set); MAME has no ST7 disassembler.
- Real code: the RabbitNet ST72264 microcode images and linker symbol files from Digi
  International's open-source release of Dynamic C 9
  ([digidotcom/DCRabbit_9](https://github.com/digidotcom/DCRabbit_9), Mozilla Public License
  2.0; copyright Z-World 2003, Digi International 2022), fetched by `test/fetch-samples.sh`
  at a pinned commit, never committed.

## Ghidra-Rare changes

All changes are commits on branch `ghidra-rare` on top of the pull request head:

1. *Pre-bytes.* A pre-byte (90, 91, 92) could be followed by another pre-byte and decode as one
   instruction; asl and the manual have no such encoding. Rejected.
2. *P-code rewrite* (`data/languages/ST7.sinc`; decode patterns unchanged): one-byte pointers
   widened with zeros, direct and computed `JP`/`CALL`/`JRxx`/`CALLR` targets separated, signed
   relative offset through a pointer, flags of ADC/ADD (H and carry in), SUB/SBC/CP (C is the
   unsigned borrow; CP had it inverted), NEG, SRA (arithmetic shift), RLC/RRC (N/Z from the
   result), BTJT/BTJF (C receives the tested bit), TRAP (stack order and vector jump), RSP, and
   macros for the stack and CC image. The exact list is in the commit message.
3. *SLEIGH lint.* `sleigh -l` reported 13 unresolvable pattern conflicts (the ones discussed in
   the pull request thread); they are gone.
4. *Spec files.* Language descriptions, an ELF opinion (`e_machine` 68, untested: no ST7 ELF
   file was available), standalone `build.gradle` and `extension.properties`, `.gitignore`.
5. *Ghidra-Rare additions:* `GHIDRA-RARE.md`, this file, `README.md`, `LICENSE` and everything
   under `test/`.
